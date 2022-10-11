from dataclasses import dataclass
import itertools
import os
from typing import Tuple
from web3._utils.abi import get_abi_output_types
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3._utils.request import async_make_post_request
from .websocket import *
from dotenv import load_dotenv

load_dotenv()

MULTICALL_ADDRESS = {
    'mainnet': '0x5BA1e12693Dc8F9c48aAD8770482f4739bEeD696',
    'goerli': '0x5BA1e12693Dc8F9c48aAD8770482f4739bEeD696',
    'polygon-mainnet': '0x275617327c958bD06b5D6b871E7f491D76113dd8',
    'avalanche-mainnet': '0xed386Fe855C1EFf2f843B910923Dd8846E45C5A4',
    'arbitrum-mainnet': '0x7a7443f8c577d537f1d8cd4a629d40a3148dd7ee',
    'optimism-mainnet': '0xeAa6877139d436Dc6d1f75F3aF15B74662617B2C'
}


@dataclass
class Call:
    target: ChecksumAddress
    call_data: Union[bytes, HexStr]
    block_identifier: BlockIdentifier

    def __hash__(self):
        return hash((self.target, self.call_data, self.block_identifier))


@dataclass
class Result:
    success: bool
    return_data: Union[bytes, HexStr]


with open('./abi/Multicall2.json') as abi:
    MULTICALL = Web3().eth.contract(MULTICALL_ADDRESS[os.environ['NETWORK']], abi=json.load(abi)['abi'])


def decode_return_data(
        web3: Web3,
        return_data: bytes,
        fn_abi: ABIFunction,
        normalizers
) -> Any:
    output_types = get_abi_output_types(fn_abi)
    output_data = web3.codec.decode_abi(output_types, return_data)
    _normalizers = itertools.chain(BASE_RETURN_NORMALIZERS, normalizers)
    normalized_data = map_abi_data(_normalizers, output_types, output_data)
    if len(normalized_data) == 1:
        return normalized_data[0]
    else:
        return normalized_data


class MulticallHTTPProvider(AsyncHTTPProvider):
    loop = asyncio.get_event_loop()
    calls: Dict[Call, asyncio.Future] = {}
    web3 = Web3()

    async def single_call(self, batch: List[Call]) -> RPCResponse:
        block_identifier = batch[0].block_identifier
        if len(batch) == 1:
            params = ({'to': batch[0].target, 'data': batch[0].call_data}, block_identifier)
            request_data = self.encode_rpc_request(RPC.eth_call, params)
            raw_response = await async_make_post_request(
                self.endpoint_uri,
                request_data,
                **self.get_request_kwargs()
            )
            response = self.decode_rpc_response(raw_response)
            response['result'] = [response['result']]
        else:
            calls = [(call.target, call.call_data) for call in batch]
            aggregate = MULTICALL.functions.aggregate(calls)
            data: HexStr = aggregate._encode_transaction_data()
            params = ({'to': MULTICALL.address, 'data': data}, block_identifier)
            request_data = self.encode_rpc_request(RPC.eth_call, params)
            raw_response = await async_make_post_request(
                self.endpoint_uri,
                request_data,
                **self.get_request_kwargs()
            )
            response = self.decode_rpc_response(raw_response)
            result = PYTHONIC_RESULT_FORMATTERS[RPC.eth_call](response['result'])
            response['result'] = decode_return_data(
                self.web3,
                result,
                aggregate.abi,
                aggregate._return_data_normalizers
            )[1]
        return response

    async def multicall(self):
        if self.calls:
            working = {}
            batches = {}
            for call in self.calls:
                working[call] = self.calls[call]
                if call.block_identifier in batches:
                    batches[call.block_identifier].append(call)
                else:
                    batches[call.block_identifier] = [call]
            self.calls.clear()
            queries = [self.single_call(batch) for batch in batches.values()]
            responses: Tuple[RPCResponse] = await asyncio.gather(*queries)
            for response, batch in zip(responses, batches.values()):
                for result, call in zip(response['result'], batch):
                    res = RPCResponse(
                        id=response['id'],
                        jsonrpc=response['jsonrpc'],
                        result=result
                    )
                    if 'error' in response:
                        res['error'] = response['error']
                    working[call].set_result(res)

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        self.logger.debug("Making request HTTP. URI: %s, Method: %s",
                          self.endpoint_uri, method)
        if method == RPC.eth_call:
            address = params[0]['to']
            data = params[0]['data']
            block_identifier: BlockIdentifier = params[-1]
            fut = self.loop.create_future()
            call = Call(address, data, block_identifier)
            self.calls[call] = fut
            self.loop.create_task(self.multicall())
            response = await fut
        else:
            request_data = self.encode_rpc_request(method, params)
            raw_response = await async_make_post_request(
                self.endpoint_uri,
                request_data,
                **self.get_request_kwargs()
            )
            response = self.decode_rpc_response(raw_response)
        self.logger.debug("Getting response HTTP. URI: %s, "
                          "Method: %s, Response: %s",
                          self.endpoint_uri, method, response)
        return response
