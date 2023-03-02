from dataclasses import dataclass
import itertools
import os
from typing import Tuple
from aiohttp import ClientTimeout
from web3.contract import (
    ContractFunction,
    DecodingError,
    ACCEPTABLE_EMPTY_STRINGS
)
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
        fn: ContractFunction
) -> Any:
    output_types = get_abi_output_types(fn.abi)
    try:
        output_data = web3.codec.decode(output_types, return_data)
    except DecodingError as e:
        # Provide a more helpful error message than the one provided by
        # eth-abi-utils
        is_missing_code_error = (
                return_data in ACCEPTABLE_EMPTY_STRINGS
                and web3.eth.get_code(fn.address) in ACCEPTABLE_EMPTY_STRINGS)
        if is_missing_code_error:
            msg = (
                "Could not transact with/call contract function, is contract "
                "deployed correctly and chain synced?"
            )
        else:
            msg = (
                f"Could not decode contract function call to {fn.function_identifier} with "
                f"return data: {str(return_data)}, output_types: {output_types}"
            )
        raise BadFunctionCallOutput(msg) from e

    _normalizers = itertools.chain(BASE_RETURN_NORMALIZERS, fn._return_data_normalizers)
    normalized_data = map_abi_data(_normalizers, output_types, output_data)
    if len(normalized_data) == 1:
        return normalized_data[0]
    else:
        return normalized_data


class MulticallHTTPProvider(AsyncHTTPProvider):
    web3 = Web3()

    def __init__(self, endpoint_uri, request_kwargs: Optional[Any] = None):
        request_kwargs = request_kwargs or {}
        request_kwargs.setdefault('timeout', ClientTimeout(10))
        self.timeout = request_kwargs['timeout'].total
        super().__init__(endpoint_uri, request_kwargs)
        self.calls: Dict[Call, asyncio.Future] = {}
        self.loop = asyncio.get_event_loop()
        self.result_formatters = get_result_formatters(RPC.eth_call, self.web3.eth)
        self.error_formatters = get_error_formatters(RPC.eth_call)

    async def single_call(self, batch: List[Call]) -> RPCResponse:
        block_identifier = batch[0].block_identifier
        if len(batch) == 1:
            params = ({'to': batch[0].target, 'data': batch[0].call_data}, block_identifier)
            response = await self._make_request(RPC.eth_call, params)
            if 'result' in response:
                response['result'] = [response['result']]
            elif 'error' in response:
                response['result'] = [response['error']]
            else:
                raise BadResponseFormat(f'Singlecall response error {response}')
        else:
            calls = [(call.target, call.call_data) for call in batch]
            aggregate = MULTICALL.functions.aggregate(calls)
            data: HexStr = aggregate._encode_transaction_data()
            params = ({'to': MULTICALL.address, 'data': data}, block_identifier)
            response = await self._make_request(RPC.eth_call, params)
            try:
                formatted_result = self.web3.manager.formatted_response(response, params, self.error_formatters)
                formatted_result = apply_result_formatters(self.result_formatters, formatted_result)
                response['result'] = decode_return_data(
                    self.web3,
                    formatted_result,
                    aggregate
                )[1]
            except ValueError as err:
                self.logger.debug(err)
                batch1, batch2 = batch[:len(batch) // 2], batch[len(batch) // 2:]
                resp1, resp2 = await asyncio.gather(self.single_call(batch1), self.single_call(batch2))
                response['result'] = resp1['result'] + resp2['result']
        return response

    async def multicall(self):
        if self.calls:
            working = {}
            batches = {}
            for call, fut in self.calls.items():
                working[call] = fut
                if call.block_identifier in batches:
                    batches[call.block_identifier].append(call)
                else:
                    batches[call.block_identifier] = [call]
            self.calls.clear()
            queries = [self.single_call(batch) for batch in batches.values()]
            responses: Tuple[RPCResponse] = await asyncio.gather(*queries)
            for response, batch in zip(responses, batches.values()):
                assert len(response['result']) == len(batch), f"Invalid multicall response: {response['result']}"
                for result, call in zip(response['result'], batch):
                    # Error expected to be a dict
                    if isinstance(result, dict):
                        res = RPCResponse(
                            id=response['id'],
                            jsonrpc=response['jsonrpc'],
                            error=result
                        )
                    else:
                        res = RPCResponse(
                            id=response['id'],
                            jsonrpc=response['jsonrpc'],
                            result=result
                        )
                    working[call].set_result(res)

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        self.logger.debug("Making request HTTP. URI: %s, Method: %s",
                          self.endpoint_uri, method)
        if method == RPC.eth_call:
            call = Call(target=params[0]['to'], call_data=params[0]['data'], block_identifier=params[-1])
            if call in self.calls:
                # Avoid duplicate call
                fut = self.calls[call]
            else:
                if not self.calls:
                    self.loop.create_task(self.multicall())
                fut = self.loop.create_future()
                self.calls[call] = fut
            try:
                response = await asyncio.wait_for(fut, self.timeout)
            except asyncio.TimeoutError:
                self.logger.warning(f'Multicall timeout {params=}')
                response = await self._make_request(method, params)
        else:
            response = await self._make_request(method, params)
        self.logger.debug("Getting response HTTP. URI: %s, "
                          "Method: %s, Response: %s",
                          self.endpoint_uri, method, response)
        return response

    async def _make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        request_data = self.encode_rpc_request(method, params)
        raw_response = await async_make_post_request(
            self.endpoint_uri,
            request_data,
            **self.get_request_kwargs()
        )
        return self.decode_rpc_response(raw_response)
