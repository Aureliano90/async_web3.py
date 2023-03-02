# [async_web3.py](https://github.com/Aureliano90/async_web3.py)

Asynchronous wrapper of `Web3` class that makes queries, builds transactions, calls contract functions, broadcasts
transactions and fetches event logs asynchronously.

### Features

* Custom `AsyncWebsocketProvider` that supports `eth_subscribe` and `eth_unsubscribe` RPC methods, listening
  to `newHeads`, `newPendingTransactions` and `logs`.
* Custom `MulticallHTTPProvider` that automatically combines concurrent `eth_call` requests into a single call
  to `Multicall` contract.

### Environment Setup

Define the following in `.env` according to the chain you use

```
WEB3_INFURA_PROJECT_ID=
WEB3_INFURA_SCHEME=https
WEB3_WS_PROVIDER_URI=
NETWORK=goerli
BLOCK_EXPLORER=https://api-goerli.etherscan.io/
EXPLORER_API_KEY=
```

Install dependencies

```
pip install -r requirements.txt
```
