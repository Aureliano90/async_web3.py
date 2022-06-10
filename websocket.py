import asyncio
from asyncio.futures import wrap_future
import json
import traceback
import websockets
from web3 import Web3, WebsocketProvider
from web3.datastructures import AttributeDict
from web3.eth import Eth
from web3.method import (
    Method,
    default_root_munger,
)
from web3.middleware import (
    buffered_gas_estimate_middleware,
    gas_price_strategy_middleware
)
from web3.module import apply_result_formatters
from web3.types import *
from web3._utils.rpc_abi import RPC, RPCEndpoint
from web3._utils.method_formatters import get_result_formatters, log_entry_formatter, receipt_formatter


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


class WebsocketSubscription:
    """Base class for Websocket subscription to node
    """
    def __init__(
            self,
            endpoint_uri: str,
            sub_type: str,
            *args,
            timeout=20,
            loop=None
    ):
        self.web3 = Web3(
            provider=WebsocketProvider(
                endpoint_uri,
                websocket_timeout=timeout
            ),
            middlewares=[gas_price_strategy_middleware, buffered_gas_estimate_middleware]
        )
        self.ws_eth = WsEth(self.web3)
        self.sub_type = sub_type
        self.args = args
        self.timeout = timeout
        self.conn = self.web3.provider.conn
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop
        self._loop = self.conn.loop
        self.subscription_id = ''

    async def __aiter__(self):
        """AsyncGenerator of Websocket feed
        """
        while True:
            try:
                self.subscription_id = self.ws_eth.subscribe(self.sub_type, *self.args)
                while True:
                    try:
                        fut = asyncio.run_coroutine_threadsafe(
                            asyncio.wait_for(self.conn.ws.recv(), self.timeout),
                            loop=self._loop
                        )
                        await wrap_future(fut, loop=self.loop)
                        fut_res = fut.result()
                        json_res = json.loads(fut_res)
                        # print(json_res)
                        res = self.processResult(json_res['params']['result'])
                        yield AttributeDict.recursive(res)
                    except (asyncio.TimeoutError, websockets.ConnectionClosed):
                        print('Websocket timed out. Subscribe again.')
                        res = self.ws_eth.unsubscribe(self.subscription_id)
                        print(self.subscription_id, 'unsubscribed', res)
                        self.close()
                        break
            except Exception:
                traceback.print_exc()
                self.close()
                break

    def close(self):
        fut = asyncio.run_coroutine_threadsafe(
            asyncio.wait_for(self.conn.ws.close(), self.timeout),
            loop=self._loop
        )
        fut.result()
        self.conn.ws = None

    def processResult(self, res):
        return res


class NewHeads(WebsocketSubscription):
    def __init__(self, endpoint_uri: str, loop=None):
        super().__init__(endpoint_uri, 'newHeads', loop=loop)

    def processResult(self, res: Dict):
        return apply_result_formatters(
            get_result_formatters(
                RPC.eth_getBlockByNumber,
                self.ws_eth),
            res)


class PendingTransactions(WebsocketSubscription):
    def __init__(self, endpoint_uri: str, loop=None):
        super().__init__(endpoint_uri, 'newPendingTransactions', loop=loop)

    def processResult(self, tx_hash: HexStr):
        return tx_hash
        # return apply_result_formatters(
        #     get_result_formatters(
        #         RPC.eth_getTransactionByHash,
        #         self.ws_eth),
        #     res)


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
        super().__init__(endpoint_uri, 'logs', params, loop=loop)

    def processResult(self, log: LogReceipt):
        return apply_result_formatters(log_entry_formatter, log)
