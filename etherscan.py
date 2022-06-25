from aweb3 import *
from datetime import datetime, timezone
import aiohttp

# os.environ['Etherscan_API_Key'] = ''
apikey = os.environ.get('Etherscan_API_Key', '')


async def etherscan_query(params: Dict) -> Any:
    async with aiohttp.client.ClientSession('https://api.etherscan.io') as client:
        async with client.get('/api', params=params) as response:
            res = await response.json()
            return res['result']


async def get_abi(contract: str) -> str:
    params = dict(module='contract', action='getabi', address=Web3.toChecksumAddress(contract), apikey=apikey)
    return await etherscan_query(params)


async def block_by_timestamp(timestamp: Union[int, datetime]) -> int:
    if isinstance(timestamp, datetime):
        timestamp = timestamp.replace(tzinfo=timezone.utc).timestamp()
    params = dict(module='block', action='getblocknobytime', timestamp=int(timestamp), closest='before', apikey=apikey)
    return int(await etherscan_query(params))


async def get_logs(from_block: int, to_block: int, address: str, **topics) -> List[LogReceipt]:
    params = dict(
        module='logs',
        action='getLogs',
        fromBlock=from_block,
        toBlock=to_block,
        address=Web3.toChecksumAddress(address),
        apikey=apikey
    )
    params.update(topics)
    return await etherscan_query(params)


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


async def get_transaction_receipt(tx_hash: HexStr) -> TxReceipt:
    params = dict(
        module='proxy',
        action='eth_getTransactionReceipt',
        txhash=tx_hash,
        apikey=apikey
    )
    res = await etherscan_query(params)
    return apply_result_formatters(receipt_formatter, res) if res else res
