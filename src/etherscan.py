import collections
import time
import attr
from .aweb3 import *
from web3._utils.method_formatters import receipt_formatter
from datetime import datetime, timezone
import aiohttp


class RateLimiter(asyncio.Semaphore):
    """A custom semaphore to be used with REST API with velocity limit under asyncio"""

    def __init__(self, concurrency: int, interval: int):
        """控制REST API访问速率

        :param concurrency: API limit
        :param interval: Reset interval
        """
        super().__init__(concurrency)
        # Queue of inquiry timestamps
        self._inquiries = collections.deque(maxlen=concurrency)
        self._loop = asyncio.get_event_loop()
        self._concurrency = concurrency
        self._interval = interval
        self._count = concurrency

    def __repr__(self):
        return f"Rate limit: {self._concurrency} inquiries/{self._interval}s"

    async def acquire(self):
        await super().acquire()
        if self._count > 0:
            self._count -= 1
        else:
            timelapse = time.monotonic() - self._inquiries.popleft()
            # Wait until interval has passed since the first inquiry in queue returned.
            if timelapse < self._interval:
                await asyncio.sleep(self._interval - timelapse)
        return True

    def release(self):
        self._inquiries.append(time.monotonic())
        super().release()


@attr.s(repr=True, slots=True)
class Etherscan:
    client: aiohttp.ClientSession = attr.ib(converter=aiohttp.ClientSession)
    apikey: str = attr.ib()
    semaphore: RateLimiter = attr.ib()

    async def close(self):
        await self.client.close()

    async def query(self, params: Dict) -> Any:
        async with self.semaphore:
            async with self.client.get('/api', params=params) as response:
                res = await response.json()
                return res['result']

    async def get_abi(self, contract: str) -> str:
        return await self.query(dict(
            module='contract',
            action='getabi',
            address=Web3.toChecksumAddress(contract),
            apikey=self.apikey
        ))

    async def block_by_timestamp(self, timestamp: Union[int, float, datetime]) -> int:
        if isinstance(timestamp, datetime):
            timestamp = timestamp.replace(tzinfo=timezone.utc).timestamp()
        return int(await self.query(dict(
            module='block',
            action='getblocknobytime',
            timestamp=int(timestamp),
            closest='before',
            apikey=self.apikey)
        ))

    async def get_logs(self, from_block: int, to_block: int, address: str, **topics) -> List[LogReceipt]:
        params = dict(
            module='logs',
            action='getLogs',
            fromBlock=from_block,
            toBlock=to_block,
            address=Web3.toChecksumAddress(address),
            apikey=self.apikey
        )
        params.update(topics)
        return await self.query(params)

    @staticmethod
    def process_logs(event: ContractEvent, logs: List[LogReceipt]) -> List[EventData]:
        processed = []
        for log in logs:
            for i, topic in enumerate(log['topics']):
                if isinstance(topic, str):
                    log['topics'][i] = decode_hex(topic)
            if 'blockHash' not in log:
                log['blockHash'] = HexBytes(0)
            processed.append(event.processLog(log))
        return processed

    async def get_transaction_receipt(self, tx_hash: HexStr) -> TxReceipt:
        res = await self.query(dict(
            module='proxy',
            action='eth_getTransactionReceipt',
            txhash=tx_hash,
            apikey=self.apikey
        ))
        return apply_result_formatters(receipt_formatter, res) if res else res

    async def get_transactions_by_address(
            self,
            address: ChecksumAddress,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=10000,
            sort: Literal['asc', 'desc'] = 'asc'
    ) -> List[Dict]:
        return await self.query(dict(
            module='account',
            action='txlist',
            address=address,
            startblock=startblock,
            endblock=endblock,
            page=page,
            offset=offset,
            sort=sort,
            apikey=self.apikey
        ))

    async def get_erc20_transfers(
            self,
            contractaddress: ChecksumAddress = '',
            address: ChecksumAddress = '',
            startblock=0,
            endblock=99999999,
            page=1,
            offset=10000,
            sort: Literal['asc', 'desc'] = 'asc'
    ) -> List[Dict]:
        params = dict(
            module='account',
            action='tokentx',
            startblock=startblock,
            endblock=endblock,
            page=page,
            offset=offset,
            sort=sort,
            apikey=self.apikey
        )
        if contractaddress: params['contractaddress'] = contractaddress
        if address: params['address'] = address
        return await self.query(params)


etherscan = Etherscan(
    os.environ['BLOCK_EXPLORER'],
    os.environ.get('EXPLORER_API_KEY', ''),
    RateLimiter(5, 1)
)
