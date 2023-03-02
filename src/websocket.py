import asyncio
from asyncio.futures import wrap_future
import json
import traceback
from typing import AsyncGenerator
import websockets
from eth_typing import HexAddress
from web3.exceptions import (
    BadFunctionCallOutput,
    BadResponseFormat,
    ContractLogicError
)
from web3.datastructures import AttributeDict
from web3.main import *
from web3.method import (
    Method,
    default_root_munger,
)
from web3.middleware import (
    async_buffered_gas_estimate_middleware,
    async_gas_price_strategy_middleware
)
from web3.module import apply_result_formatters, retrieve_async_method_call_fn
from web3.types import *
from web3._utils.rpc_abi import RPC, RPCEndpoint
from web3._utils.method_formatters import (
    get_result_formatters,
    get_error_formatters,
    log_entry_formatter
)


class WsEth(Eth):
    """Websocket Eth
    """
    subscribe = Method(
        RPCEndpoint('eth_subscribe'),
        mungers=[default_root_munger],
    )

    unsubscribe = Method(
        RPCEndpoint('eth_unsubscribe'),
        mungers=[default_root_munger],
    )


class AsyncWebsocketProvider(WebsocketProvider):
    request_func = AsyncHTTPProvider.request_func
    _generate_request_func = AsyncHTTPProvider._generate_request_func
    isConnected = AsyncHTTPProvider.isConnected

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        self.logger.debug("Making request WebSocket. URI: %s, "
                          "Method: %s", self.endpoint_uri, method)
        request_data = self.encode_rpc_request(method, params)
        future = asyncio.run_coroutine_threadsafe(
            self.coro_make_request(request_data),
            WebsocketProvider._loop
        )
        await wrap_future(future, loop=asyncio.get_running_loop())
        return future.result()


class WebsocketSubscription:
    """Base class for Websocket subscription to node
    """

    def __init__(
            self,
            endpoint_uri: str,
            sub_type: str,
            params: Optional[Dict] = None,
            timeout=40,
            loop=None
    ):
        self.endpoint_uri = endpoint_uri
        self.web3 = Web3(
            provider=AsyncWebsocketProvider(
                endpoint_uri,
                websocket_timeout=timeout
            ),
            middlewares=[async_gas_price_strategy_middleware, async_buffered_gas_estimate_middleware]
        )
        self.ws_eth = WsEth(self.web3)
        self.ws_eth.is_async = True
        self.ws_eth.retrieve_caller_fn = retrieve_async_method_call_fn(self.web3, self.ws_eth)
        self.sub_type = sub_type
        self.params = [params] if params else []
        self.timeout = timeout
        self.conn = self.web3.provider.conn
        # Current event loop
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop
        # Event loop in another thread
        self._loop = self.conn.loop
        self.subscription_id = ''

    async def coroutine_different_loop(self, coro):
        """Coroutine that submits a coroutine object to a different event loop
        """
        fut = asyncio.run_coroutine_threadsafe(
            asyncio.wait_for(coro, self.timeout),
            loop=self._loop
        )
        await wrap_future(fut, loop=self.loop)
        return fut.result()

    async def connect(self):
        self.conn.ws = await self.coroutine_different_loop(
            websockets.connect(
                uri=self.endpoint_uri,
                loop=self._loop,
                **self.conn.websocket_kwargs
            )
        )

    async def close(self):
        if self.conn.ws:
            await self.coroutine_different_loop(self.conn.ws.close())
        self.conn.ws = None

    async def __aiter__(self):
        """AsyncGenerator of Websocket feed
        """
        while True:
            try:
                self.subscription_id = await self.ws_eth.subscribe(self.sub_type, *self.params)
                while True:
                    try:
                        fut_res = await self.coroutine_different_loop(self.conn.ws.recv())
                        json_res = json.loads(fut_res)
                        res = AttributeDict.recursive(json_res['params']['result'])
                        yield self.process_result(res)
                    except asyncio.TimeoutError:
                        try:
                            res = await self.ws_eth.unsubscribe(self.subscription_id)
                        except BadResponseFormat:
                            pass
                        await self.close()
                        break
            except websockets.ConnectionClosed:
                await self.connect()
            except websockets.InvalidStatusCode:
                continue
            except Exception:
                traceback.print_exc()
                await self.close()

    def process_result(self, res):
        return res


class NewHeads(WebsocketSubscription):
    def __init__(self, endpoint_uri: str, loop=None):
        """Websocket generator of new blocks
        """
        super().__init__(endpoint_uri, 'newHeads', loop=loop)
        self.formatter = get_result_formatters(RPC.eth_getBlockByNumber, self.ws_eth)
        self.current: Optional[BlockData] = None

    async def __aiter__(self) -> AsyncGenerator[BlockData, None]:
        async for block in super().__aiter__():
            if self.current is None:
                yield block
            else:
                if block.number > self.current.number:
                    while block.number - self.current.number > 1:
                        try:
                            next_block = await self.ws_eth.get_block(self.current.number + 1)
                            yield next_block
                            self.current = next_block
                        except BadResponseFormat:
                            pass
                    yield block
            self.current = block

    def process_result(self, res: AttributeDict) -> BlockData:
        return apply_result_formatters(self.formatter, res)


class AlchemyPendingFilter(TypedDict):
    fromAddress: Union[HexAddress, List[HexAddress]]
    toAddress: Union[HexAddress, List[HexAddress]]
    hashesOnly: bool


class PendingTransactions(WebsocketSubscription):
    def __init__(
            self,
            endpoint_uri: str,
            params: Optional[AlchemyPendingFilter] = None,
            loop=None
    ):
        """Websocket generator of pending transactions
        """
        if 'alchemy' in endpoint_uri:
            super().__init__(endpoint_uri, 'alchemy_pendingTransactions', params=params, loop=loop)
        else:
            super().__init__(endpoint_uri, 'newPendingTransactions', loop=loop)
        self.formatter = get_result_formatters(RPC.eth_getTransactionByHash, self.ws_eth)

    def process_result(self, tx: Union[AttributeDict, HexStr]) -> Union[TxData, HexStr]:
        if isinstance(tx, AttributeDict):
            return apply_result_formatters(self.formatter, tx)
        else:
            return tx


class Logs(WebsocketSubscription):
    def __init__(
            self,
            endpoint_uri: str,
            address: Optional[Union[ChecksumAddress, List[ChecksumAddress]]] = None,
            topics: Optional[Sequence[str]] = None,
            loop=None
    ):
        params = {}
        if address:
            params['address'] = address
        if topics:
            params['topics'] = list(topics)
        super().__init__(endpoint_uri, 'logs', params=params, loop=loop)

    def process_result(self, log: AttributeDict) -> LogReceipt:
        return apply_result_formatters(log_entry_formatter, log)
