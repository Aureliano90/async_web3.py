import functools
import itertools
import os
from types import MethodType
from eth_account import Account
from eth_account.datastructures import SignedTransaction
from eth_utils import *
from eth_utils.toolz import merge
from web3.auto.infura import *
from web3.contract import (
    Contract,
    ContractFunction,
    ContractEvent,
    prepare_transaction
)
from web3._utils.abi import get_abi_output_types
from web3._utils.empty import Empty
from web3._utils.filters import Filter, LogFilter
from web3._utils.module import attach_modules
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from websocket import *
import middleware
import rlp

if not os.environ.get('WEB3_WS_PROVIDER_URI'):
    os.environ['WEB3_INFURA_SCHEME'] = 'wss'
    os.environ['WEB3_WS_PROVIDER_URI'] = build_infura_url(INFURA_MAINNET_DOMAIN)


class aWeb3(Web3):
    """Asynchronous Web3 class
    """
    # Async Eth
    eth: Eth
    loop = asyncio.get_event_loop()
    newHeads: AsyncGenerator[BlockData, None] = NewHeads(os.environ['WEB3_WS_PROVIDER_URI'], loop=loop)
    pendingTransactions: Callable[[Optional[AlchemyPendingFilter]], AsyncGenerator[TxData, None]] = functools.partial(
        PendingTransactions,
        os.environ['WEB3_WS_PROVIDER_URI'], loop=loop)

    def __new__(cls, endpoint_uri: str):
        obj = super().__new__(cls)
        # Necessary to subclass Web3
        obj.attach_modules = MethodType(lambda self, modules: attach_modules(self, modules, self), obj)
        return obj

    def __init__(self, endpoint_uri: str):
        super().__init__(
            provider=AsyncHTTPProvider(endpoint_uri),
            middlewares=[
                async_gas_price_strategy_middleware,
                async_buffered_gas_estimate_middleware,
                middleware.async_latest_block_based_cache_middleware
            ]
        )
        self.eth.is_async = True
        self.eth.retrieve_caller_fn = retrieve_async_method_call_fn(self, self.eth)
        self._eth = Web3(provider=HTTPProvider(endpoint_uri)).eth
        self._nonce = Nonce(0)

    @property
    def default_account(self) -> Union[ChecksumAddress, Empty]:
        """Default address
        """
        return self.eth.default_account

    @default_account.setter
    def default_account(self, account: Union[ChecksumAddress, Empty]):
        self.eth.default_account = account

    async def create_account(self, key: Union[str, bytes] = ''):
        """Create wallet from private keys or mnemonics
        """
        if isinstance(key, str):
            if len(key.split()) > 1:
                Account.enable_unaudited_hdwallet_features()
                self.eth.account = Account.from_mnemonic(key)
            else:
                self.eth.account = Account.from_key(key)
        elif isinstance(key, bytes):
            self.eth.account = Account.from_key(key)
        else:
            self.eth.account = Account.create()
        self.default_account = self.eth.account.address
        self.nonce = await self.get_transaction_count()

    @property
    def nonce(self) -> Nonce:
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        self._nonce = value

    def null_address(self) -> ChecksumAddress:
        return self.codec.decode_single('address', self.codec.encode_single('bytes32', ''))

    async def get_transaction_count(
            self,
            account: Union[AnyAddress, ENS] = '',
            block_identifier: Optional[BlockIdentifier] = None
    ) -> Nonce:
        if not account:
            account = self.default_account
        return await self.eth.get_transaction_count(
            self.toChecksumAddress(account),
            block_identifier
        )

    async def get_balance(
            self,
            account: Union[AnyAddress, ENS] = '',
            block_identifier: Optional[BlockIdentifier] = None
    ) -> int:
        """Ether balance
        """
        if not account:
            account = self.default_account
        return self.fromWei(
            await self.eth.get_balance(
                self.toChecksumAddress(account),
                block_identifier
            ),
            'ether'
        )

    def contract(
            self,
            address: Union[AnyAddress, str, ENS],
            abi: Union[str, List[Dict]],
            **kwargs: Any
    ) -> Contract:
        """Create contract

        :param address: Contract address
        :param abi: Contract abi
        :param kwargs:
        :return: `Contract` instance
        """
        if isinstance(abi, str):
            abi = json.loads(abi)
        if not isinstance(abi, list):
            raise ValueError('ABI should be a list.')
        return self.eth.contract(
            self.toChecksumAddress(address),
            abi=abi,
            **kwargs
        )

    async def contract_address(
            self,
            creator: AnyAddress,
            nonce: Optional[Nonce] = None,
            block_identifier: Optional[BlockIdentifier] = None
    ) -> HexStr:
        if nonce is None:
            nonce = await self.eth.get_transaction_count(self.toChecksumAddress(creator), block_identifier)
        return encode_hex(keccak(rlp.encode([to_canonical_address(creator), nonce]))[12:])

    async def token_balance(
            self,
            token_contract: Contract,
            address: AnyAddress = '',
    ) -> int:
        """Query token balance

        :param token_contract: `Contract` instance of token
        :param address: Holder address
        """
        if not address:
            address = self.default_account
        fn = token_contract.functions.balanceOf(self.toChecksumAddress(address))
        return self.fromWei(await self.call(fn), 'ether')

    async def estimate_gas(
            self,
            transaction: TxParams,
            block_identifier: Optional[BlockIdentifier] = None
    ) -> TxParams:
        default_tx = TxParams(
            gas=transaction['gas'] if transaction.get('gas') else
            await self.eth.estimate_gas(transaction, block_identifier),
            chainId=transaction['chainId'] if transaction.get('chainId') else
            await self.eth.chain_id
        )
        if 'gasPrice' in transaction:
            if transaction['gasPrice']:
                default_tx['gasPrice'] = transaction['gasPrice']
            else:
                default_tx['gasPrice'] = await self.eth.generate_gas_price(
                    transaction) or await self.eth.gas_price
        else:
            max_priority_fee = transaction['maxPriorityFeePerGas'] if transaction.get('maxPriorityFeePerGas') else \
                await self.eth.max_priority_fee
            default_tx['maxPriorityFeePerGas'] = max_priority_fee
            default_tx['maxFeePerGas'] = transaction['maxFeePerGas'] if transaction.get('maxFeePerGas') else \
                max_priority_fee + 2 * (await self.eth.get_block('latest'))['baseFeePerGas']
        return merge(transaction, default_tx)

    def prepare_transaction(
            self,
            fn: ContractFunction,
            fn_args: Optional[Sequence] = None,
            fn_kwargs: Optional[Dict] = None,
            transaction: Optional[TxParams] = None,
    ) -> TxParams:
        """Prepare transaction for contract function

        :param fn: `ContractFunction` instance
        :param fn_args: Positional arguments of contract function
        :param fn_kwargs: Keyword arguments of contract function
        :param transaction: Transaction parameters
        :return: Transaction as `TxParams`
        """
        if fn_args:
            if len(fn_args) == len(fn.args):
                fn.args = fn_args
            else:
                raise ValueError('Override existing arguments with the same number of arguments.')
        if fn_kwargs:
            if len(fn_kwargs) == len(fn.kwargs):
                fn.kwargs = fn_kwargs
            else:
                raise ValueError('Override existing arguments with the same number of arguments.')
        transaction = {} if transaction is None else transaction
        if self.default_account is not empty:
            transaction.setdefault('from', self.default_account)
        return prepare_transaction(
            fn.address,
            self,
            fn_identifier=fn.function_identifier,
            contract_abi=fn.contract_abi,
            fn_abi=fn.abi,
            transaction=transaction,
            fn_args=fn.args,
            fn_kwargs=fn.kwargs,
        )

    async def build_transaction(
            self,
            fn: ContractFunction,
            fn_args: Optional[Sequence] = None,
            fn_kwargs: Optional[Dict] = None,
            transaction: Optional[TxParams] = None
    ) -> TxParams:
        """Build transaction to be signed and sent

        :param fn: `ContractFunction` instance
        :param fn_args: Positional arguments of contract function
        :param fn_kwargs: Keyword arguments of contract function
        :param transaction: Transaction parameters
        :return: Transaction as `TxParams`
        """
        prepared_tx = self.prepare_transaction(
            fn,
            fn_args,
            fn_kwargs,
            transaction
        )
        gas_tx = await self.estimate_gas(prepared_tx)
        gas_tx.pop('data')
        gas_tx.pop('to')
        return fn.buildTransaction(gas_tx)

    async def call(
            self,
            fn: ContractFunction,
            fn_args: Optional[Sequence] = None,
            fn_kwargs: Optional[Dict] = None,
            transaction: Optional[TxParams] = None,
            block_identifier: Optional[BlockIdentifier] = None,
            state_override: Optional[CallOverrideParams] = None
    ) -> Any:
        """Query contract function

        :param fn: `ContractFunction` instance
        :param fn_args: Positional arguments of contract function
        :param fn_kwargs: Keyword arguments of contract function
        :param transaction: Transaction parameters
        :param block_identifier:
        :param state_override:
        :return: Query result
        """
        prepared_tx = self.prepare_transaction(
            fn,
            fn_args,
            fn_kwargs,
            transaction
        )
        return_data = await self.eth.call(prepared_tx, block_identifier, state_override)
        return self.decode_return_data(return_data, fn.abi, fn._return_data_normalizers)

    def decode_return_data(
            self,
            return_data: bytes,
            fn_abi,
            normalizers
    ) -> Any:
        output_types = get_abi_output_types(fn_abi)
        output_data = self.codec.decode_abi(output_types, return_data)
        _normalizers = itertools.chain(BASE_RETURN_NORMALIZERS, normalizers)
        normalized_data = map_abi_data(_normalizers, output_types, output_data)
        if len(normalized_data) == 1:
            return normalized_data[0]
        else:
            return normalized_data

    async def send_raw_transaction(self, transaction: Union[HexStr, bytes]) -> HexBytes:
        return await self.eth.send_raw_transaction(transaction)

    def sign_transaction(self, transaction: TxParams) -> SignedTransaction:
        if 'nonce' not in transaction:
            transaction['nonce'] = self.nonce
        return self.eth.account.sign_transaction(transaction)

    async def send_transaction(self, transaction: TxParams) -> HexBytes:
        """Sign and broadcast
        """
        self.nonce += 1
        signed_tx = self.sign_transaction(transaction)
        return await self.send_raw_transaction(signed_tx.rawTransaction)

    async def get_transaction_receipt(self, tx_hash: Union[HexStr, HexBytes]) -> TxReceipt:
        return await self.eth.get_transaction_receipt(HexBytes(tx_hash))

    async def transfer_eth(
            self,
            target_address: AnyAddress,
            amount,
            data='',
            transaction: Optional[TxParams] = None
    ) -> HexBytes:
        """Transfer Ether
        """
        default_tx = {
            'nonce': self.nonce,
            'from': self.default_account,
            'to': self.toChecksumAddress(target_address),
            'value': self.toWei(amount, 'ether'),
            'data': encode_hex(data),
            'gas': 21000
        }
        transaction = default_tx if transaction is None else merge(default_tx, transaction)
        tx_hash = await self.send_transaction(transaction)
        return tx_hash

    async def transfer_token(
            self,
            token_contract: Contract,
            target_address: AnyAddress,
            amount,
            transaction: Optional[TxParams] = None
    ) -> HexBytes:
        """Transfer ERC20
        """
        target_address = self.toChecksumAddress(target_address)
        default_tx = {
            'nonce': self.nonce,
            'from': self.default_account,
            'to': token_contract.address,
            'value': 0
        }
        transaction = default_tx if transaction is None else merge(default_tx, transaction)
        fn = token_contract.functions.transfer(target_address, self.toWei(amount, "ether"))
        tx = await self.build_transaction(fn, transaction=transaction)
        tx_hash = await self.send_transaction(tx)
        return tx_hash

    async def get_new_pending(self) -> List[LogReceipt]:
        _filter = await self.eth.filter('pending')
        log_entries = _filter._filter_valid_entries(await self.eth.get_filter_changes(_filter.filter_id))
        return _filter._format_log_entries(log_entries)

    def create_filter(
            self,
            event: ContractEvent,
            filter_params: Optional[FilterParams] = None,
            **argument_filters
    ) -> LogFilter:
        """Create event log filter

        :param event: Contract event
        :param filter_params: Filter parameters including address, fromBlock, toBlock, topics
        :param argument_filters: Dictionary of event arguments and their matching values
        :return: Log filter
        """
        if type(event.web3).__name__ != 'Web3':
            event.web3 = self._eth.web3
        return event.createFilter(
            fromBlock=filter_params.get('fromBlock'),
            toBlock=filter_params.get('toBlock'),
            topics=filter_params.get('topics'),
            argument_filters=argument_filters
        )

    async def get_log_entries(self, log_filter: Filter) -> List[LogReceipt]:
        """Get all log entries
        """
        logs = await self.eth.get_filter_logs(log_filter.filter_id)
        log_entries = log_filter._filter_valid_entries(logs)
        return log_filter._format_log_entries(log_entries)

    async def get_log_changes(self, log_filter: Filter) -> List[LogReceipt]:
        """Get new log entries
        """
        logs = await self.eth.get_filter_changes(log_filter.filter_id)
        log_entries = log_filter._filter_valid_entries(logs)
        return log_filter._format_log_entries(log_entries)

    async def get_logs(
            self,
            event: Optional[ContractEvent] = None,
            address: Optional[Union[AnyAddress, Sequence[AnyAddress]]] = None,
            topics: Optional[Sequence[str]] = None,
    ) -> AsyncGenerator[EventData, None]:
        """AsyncGenerator of logs

        :param event: Contract event
        :param address: An address or an array of addresses.
                        Only logs that are created from these addresses are returned
        :param topics: Only logs which match the specified topics
        """
        if event:
            address = event.address
            if topics is None:
                topics = [encode_hex(event_abi_to_log_topic(event.abi))]
        if address:
            try:
                address = self.toChecksumAddress(address)
            except ValueError:
                address = list(map(self.toChecksumAddress, list(address)))
        async for log in Logs(
                os.environ['WEB3_WS_PROVIDER_URI'],
                address=address,
                topics=topics,
                loop=self.loop
        ):
            yield event.processLog(log) if event else log

    async def txs_by_block(self, block_number: int) -> AsyncGenerator[TxData, None]:
        """AsyncGenerator of new transactions
        """
        block = await self.eth.get_block(block_number, full_transactions=True)
        for tx in block.transactions:
            yield tx

    async def new_blocks(self) -> AsyncGenerator[BlockData, None]:
        """Alternative newHeads without Websocket
        """
        prev = block = await self.eth.get_block('latest', full_transactions=True)
        yield block
        while True:
            block = await self.eth.get_block('latest', full_transactions=True)
            if block.number > prev.number:
                if block.number - prev.number > 1:
                    prev = block = await self.eth.get_block(prev.number + 1, full_transactions=True)
                yield block
            await asyncio.sleep(1)

    @staticmethod
    async def decode_pending(contract: Contract, tx: TxData):
        return contract.decode_function_input(tx.input)
