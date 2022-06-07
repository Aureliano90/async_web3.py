from aweb3 import *
from datetime import datetime, timezone
import aiohttp

apikey = ''


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


async def get_logs(from_block: int, to_block: int, address: str, **topics) -> List[Dict]:
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
