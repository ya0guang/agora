import secrets

from web3 import Web3, HTTPProvider

from .compile import *
from .config import CONFIG, SOURCE_PATH


CONTRACT = None


w3 = Web3(HTTPProvider(CONFIG['provider']))

def get_contract():
    global CONTRACT
    if CONTRACT is not None:
        return CONTRACT
    else:
        with open(SOURCE_PATH, 'r') as f:
            contract_source = f.read()
            contract = compile_from_src(contract_source, NAME)
            CONTRACT = contract
            return contract


def generate_private_key():
    secret = "0x" + secrets.token_hex(32)
    account = w3.eth.account.from_key(secret)
    return secret, account.address


def publish_task(private_key, contract_addr, file_hash, file_name, constraints):
    # initialize contract
    contract = get_contract()
    abi = contract['abi']

    contract = w3.eth.contract(address=contract_addr, abi=abi)
    # check if the bug bounty task already exists
    bounty_info = contract.functions.bugBounties(file_hash).call()
    if bounty_info[0]:
        print("Task with hash {} already exists.".format(file_hash.hex()))
        return None
    # get function
    func = contract.functions.publishTask(file_hash, file_name, constraints)
    # get address and nonce
    address = w3.eth.account.from_key(private_key).address
    nonce = w3.eth.get_transaction_count(address)
    # params
    gas_price = w3.eth.gas_price
    gas_estimate = func.estimate_gas({
        'from': address,
        'nonce': nonce
    })
    # build transaction
    transaction = func.build_transaction({
        'gas': gas_estimate,
        'gasPrice': gas_price,
        'from': address,
        'nonce': nonce
    })
    # sign transaction
    signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    # send transaction
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    # wait for the transaction to be mined and get the transaction receipt
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    return transaction_receipt


def verify_bug(private_key, contract_addr, hash):
    # initialize contract
    contract = get_contract()
    abi = contract['abi']
    
    contract = w3.eth.contract(address=contract_addr, abi=abi)
    # check if the bug bounty task exists
    bounty_info = contract.functions.bugBounties(hash).call()
    if not bounty_info[0]:
        print("Task with hash {} does not exist.".format(hash.hex()))
        return None
    # get function
    func = contract.functions.verifyBug(hash)
    # get address and nonce
    address = w3.eth.account.from_key(private_key).address
    nonce = w3.eth.get_transaction_count(address)
    # transaction params
    gas_price = w3.eth.gas_price
    gas_estimate = func.estimate_gas({
        'from': address,
        'nonce': nonce
    })
    # build transaction
    transaction = func.build_transaction({
        'gas': gas_estimate,
        'gasPrice': gas_price,
        'from': address,
        'nonce': nonce
    })
    # sign transaction
    signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    # send transaction
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    # wait for the transaction to be mined and get the transaction receipt
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    return transaction_receipt


def submit_bug(private_key, contract_addr, hash, attestation):
    # initialize contract
    contract = get_contract()
    abi = contract['abi']

    contract = w3.eth.contract(address=contract_addr, abi=abi)
    # get function
    func = contract.functions.submitBug(hash, attestation)
    # get address and nonce
    address = w3.eth.account.from_key(private_key).address
    nonce = w3.eth.get_transaction_count(address)
    # transaction params
    gas_price = w3.eth.gas_price
    gas_estimate = func.estimate_gas({
        'from': address,
        'nonce': nonce
    })
    # build transaction
    transaction = func.build_transaction({
        'gas': gas_estimate,
        'gasPrice': gas_price,
        'from': address,
        'nonce': nonce
    })
    # sign transaction
    signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    # send transaction
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    # wait for the transaction to be mined and get the transaction receipt
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    return transaction_receipt


def print_receipt(transaction_receipt):
    transaction_hash = transaction_receipt["transactionHash"].hex()
    print("Transaction 0x{} is mined in block: {}".format(transaction_hash, transaction_receipt["blockNumber"]))
    print("View transaction on {}/tx/0x{}".format(CONFIG['browser'], transaction_hash))
