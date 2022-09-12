import os

os.environ['WEB3_INFURA_PROJECT_ID'] = '9aa3d95b3bc440fa88ea12eaa4456161'
os.environ['WEB3_WS_PROVIDER_URI'] = f"wss://kovan.infura.io/ws/v3/{os.environ['WEB3_INFURA_PROJECT_ID']}"
os.environ['Etherscan_API_Key'] = ''

from src.etherscan import *
from pprint import pprint


async def main():
    # https://faucets.chain.link/
    web3 = aWeb3(f"https://kovan.infura.io/v3/{os.environ['WEB3_INFURA_PROJECT_ID']}")
    await web3.create_account('0xc77f20b0a53e49d82ec6ccff998e03e58d09334c6ddc142f0bec883149d3b218')
    print(web3.default_account)
    print(encode_hex(web3.eth.account.key))
    LINK = web3.toChecksumAddress('0xa36085F69e2889c224210F603D836748e7dC0088')
    token_contract = web3.contract(LINK, abi=await get_abi('0x514910771AF9Ca656af840dff83E8264EcF986CA'))
    balanceOf = token_contract.functions.balanceOf(web3.default_account)
    res = await web3.call(balanceOf)
    pprint(res)
    to_address = web3.toChecksumAddress('0xAB78e2D4C131fe44755140F5bdEbD9beA25a3c8C')
    transfer = token_contract.functions.transfer(to_address, web3.toWei(0.1, 'ether'))
    transaction = await web3.build_transaction(transfer)
    signed_transaction = web3.sign_transaction(transaction)
    tx_hash = await web3.send_raw_transaction(signed_transaction.rawTransaction)
    pprint(tx_hash)
    # tx_hash = await web3.transfer_token(token_contract, to_address, 0.1, dict(gasPrice=web3.toWei(2.5, 'gwei')))
    # pprint(tx_hash)
    async for res in web3.pendingTransactions(dict(toAddress=LINK)):
        print(res)
        if tx_hash.hex() == res:
            print('In the mempool.')
            break


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
