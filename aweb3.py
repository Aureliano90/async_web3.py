import asyncio
import itertools
import json
from typing import Any, Optional, Union
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import (
    Address,
    ChecksumAddress,
    HexStr,
)
from eth_utils.toolz import merge
from hexbytes import HexBytes
from web3 import (
    HTTPProvider,
    Web3
)
from web3._utils.abi import (
    get_abi_output_types,
    map_abi_data,
)
from web3._utils.empty import (
    Empty,
    empty,
)
from web3._utils.module import attach_modules as _attach_modules
from web3._utils.normalizers import BASE_RETURN_NORMALIZERS
from web3.contract import (
    Contract,
    ContractFunction,
    prepare_transaction
)
from web3.eth import AsyncEth
from web3.middleware import (
    buffered_gas_estimate_middleware,
    gas_price_strategy_middleware,
)
from web3.tools.benchmark.main import build_async_w3_http
from web3.tools.benchmark.utils import wait_for_http
from web3.types import (
    ENS,
    BlockIdentifier,
    CallOverrideParams,
    Nonce,
    TxParams,
)


class aWeb3(Web3):
    account: LocalAccount = Account()
    aeth: AsyncEth
    endpoint_uri: str

    def __init__(self, endpoint_uri: str):
        wait_for_http(endpoint_uri)

        def attach_modules(self, modules):
            _attach_modules(self, modules, self)

        Web3.attach_modules = attach_modules
        super().__init__(
            provider=HTTPProvider(endpoint_uri),
            middlewares=[gas_price_strategy_middleware, buffered_gas_estimate_middleware]
        )
        self.endpoint_uri = endpoint_uri
        self._nonce = Nonce(0)

    def __await__(self):
        aweb3 = yield from asyncio.create_task(build_async_w3_http(self.endpoint_uri))
        self.__setattr__('aeth', aweb3.eth)
        return self

    @property
    def default_account(self) -> Union[ChecksumAddress, Empty]:
        return self.eth.default_account

    @default_account.setter
    def default_account(self, account: Union[ChecksumAddress, Empty]) -> None:
        self.eth.default_account = account
        self.aeth.default_account = account

    def create_account(self, key: Union[str, bytes] = ''):
        if not key:
            self.account = Account.create()
        elif isinstance(key, bytes):
            self.account = Account.from_key(key)
        elif len(key.split()) > 1:
            self.account = Account.from_mnemonic(key)
        else:
            self.account = Account.from_key(key)
        self.default_account = self.account.address

    @property
    def nonce(self) -> Nonce:
        if self._nonce == 0:
            self._nonce = self.eth.get_transaction_count()
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        self._nonce = value

    async def get_transaction_count(
            self,
            account: Union[Address, ChecksumAddress, ENS] = '',
            block_identifier: Optional[BlockIdentifier] = None
    ) -> Nonce:
        if not account:
            account = self.default_account
        self.nonce = await self.aeth.get_transaction_count(account, block_identifier)
        return self.nonce

    async def get_balance(
            self,
            account: Union[Address, ChecksumAddress, ENS] = '',
            block_identifier: Optional[BlockIdentifier] = None
    ) -> int:
        if not account:
            account = self.default_account
        return self.fromWei(await self.aeth.get_balance(account, block_identifier), 'ether')

    def contract(
            self,
            address: Optional[Union[Address, ChecksumAddress, ENS]],
            abi,
            **kwargs: Any
    ) -> Contract:
        if isinstance(abi, str):
            abi = json.loads(abi)
        if not isinstance(abi, list):
            raise ValueError('ABI should be a list.')
        return self.eth.contract(self.toChecksumAddress(address), abi=abi, **kwargs)

    async def token_balance(
            self,
            token_contract: Contract,
            address: Union[Address, ChecksumAddress] = '',
    ) -> int:
        if not address:
            address = self.default_account
        address = self.toChecksumAddress(address)
        fn = token_contract.functions.balanceOf(address)
        return self.fromWei(await self.call(fn), 'ether')

    async def estimate_gas(
            self,
            transaction: TxParams,
            block_identifier: Optional[BlockIdentifier] = None
    ) -> TxParams:
        default_tx = dict(
            gas=transaction['gas'] if transaction.get('gas') else
            await self.aeth.estimate_gas(transaction, block_identifier),
            chainId=transaction['chainId'] if transaction.get('chainId') else
            await self.aeth.chain_id)
        if 'gasPrice' in transaction:
            if transaction['gasPrice']:
                default_tx['gasPrice'] = transaction['gasPrice']
            else:
                default_tx['gasPrice'] = await self.aeth.generate_gas_price(transaction) or await self.aeth.gas_price
        else:
            max_priority_fee = await self.aeth.max_priority_fee
            default_tx['maxFeePerGas'] = max_priority_fee + (2 * (await self.aeth.get_block('latest'))['baseFeePerGas'])
            default_tx['maxPriorityFeePerGas'] = max_priority_fee
        return merge(transaction, default_tx)

    async def prepare_transaction(
            self,
            fn: ContractFunction,
            *fn_args,
            transaction: Optional[TxParams] = None,
            **fn_kwargs
    ) -> TxParams:
        fn.args = fn_args if not fn.args else fn.args + fn_args
        fn.kwargs = fn_kwargs if not fn.kwargs else fn.kwargs + fn_kwargs
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
            *fn_args,
            transaction: Optional[TxParams] = None,
            **fn_kwargs
    ) -> TxParams:
        prepared_tx = await self.prepare_transaction(
            fn,
            *fn_args,
            transaction=transaction,
            **fn_kwargs
        )
        gas_tx = await self.estimate_gas(prepared_tx)
        gas_tx.pop('data')
        gas_tx.pop('to')
        return fn.buildTransaction(gas_tx)

    async def call(
            self,
            fn: ContractFunction,
            *fn_args,
            transaction: Optional[TxParams] = None,
            block_identifier: Optional[BlockIdentifier] = None,
            state_override: Optional[CallOverrideParams] = None,
            **fn_kwargs):
        prepared_tx = await self.prepare_transaction(
            fn,
            *fn_args,
            transaction=transaction,
            **fn_kwargs
        )
        return_data = await self.aeth.call(prepared_tx, block_identifier, state_override)
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

    async def send_transaction(self, transaction: TxParams) -> HexBytes:
        if 'nonce' not in transaction:
            transaction['nonce'] = self.nonce
        self.nonce += 1
        return await self.aeth.send_transaction(transaction)

    async def send_raw_transaction(self, transaction: Union[HexStr, bytes]) -> HexBytes:
        return await self.aeth.send_raw_transaction(transaction)

    async def get_transaction_receipt(self, tx_hash: HexBytes):
        return await self.aeth.get_transaction_receipt(tx_hash)

    async def transfer_eth(
            self,
            target_address: Union[Address, ChecksumAddress],
            amount,
            gasPrice=5
    ) -> HexBytes:
        transaction = {
            'nonce': self.nonce,
            'from': self.default_account,
            'to': self.toChecksumAddress(target_address),
            'value': self.toWei(amount, 'ether'),
            'gas': 21000,
            'gasPrice': self.toWei(gasPrice, 'gwei'),
        }
        signed_tx = self.account.sign_transaction(transaction)
        tx_hash = await self.send_transaction(signed_tx)
        return tx_hash

    async def transfer_token(
            self,
            token_contract: Contract,
            target_address,
            amount,
            gasPrice=5
    ) -> HexBytes:
        target_address = self.toChecksumAddress(target_address)
        transaction = {
            'nonce': self.nonce,
            'from': self.default_account,
            'to': target_address,
            'value': 0,
            'gasPrice': self.toWei(gasPrice, 'gwei')
        }
        fn = token_contract.functions.transfer(target_address, self.toWei(amount, "ether"))
        tx = await self.build_transaction(fn, transaction=transaction)
        signed_tx = self.account.sign_transaction(tx)
        tx_hash = await self.send_transaction(signed_tx)
        return tx_hash
