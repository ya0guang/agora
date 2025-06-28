import json
from solcx import compile_source
import os
import sys

from cryptography import x509
from web3 import Web3


CONFIG = "./config.json"
NAME = "BugBountyPlatform"

source_path = os.environ.get("CONTRACT_SOURCE", "../contract.sol")
solc_path = os.environ.get("SOLCX_BINARY_PATH", "/usr/bin/solc")

with open(CONFIG) as f:
    config = json.load(f)

# init web3
w3 = Web3(Web3.HTTPProvider(config["provider"]))
# init account
account = w3.eth.account.from_key(config["privateKey"])

# compile contract from source
def compile_from_src(source, contract_name):
    compiled_sol = compile_source(source, output_values=["abi", "bin", "bin-runtime"], solc_binary=solc_path)
    for name, contract in compiled_sol.items():
        if contract_name in name:
            return contract


# get contract address
def get_contract_addr(tx_hash):
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert tx_receipt != None
    return tx_receipt['contractAddress']


# deploy contract
def depoly_contract(value):
    with open(source_path, 'r') as f:
        contract_source = f.read()

    contract = compile_from_src(contract_source, NAME)

    instance = w3.eth.contract(
        abi=contract['abi'],
        bytecode=contract['bin']
    )

    pubkeys = []
    for cert in config["Certificates"]:
        cert = x509.load_pem_x509_certificate(cert.encode())
        pubkey = cert.public_key().public_numbers()
        pubkeys.append("0x{:064x}{:064x}".format(pubkey.x, pubkey.y))

    constructor = instance.constructor(
        config["ProofCheckers"],
        config["BugVerifiers"],
        config["P256SHA256"],
        config["BugVerifierMRENCLAVE"],
        pubkeys,
        config["Certificates"]
    )

    constructor_tx = constructor.build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'value': w3.to_wei(value, 'ether'),
        'gasPrice': w3.eth.gas_price
    })

    signed_tx = account.sign_transaction(constructor_tx)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print("Deploy Successfully! Transaction Hash: ", tx_hash.hex())
    except Exception as err:
        raise err

    contract_addr = get_contract_addr(tx_hash)
    return contract_addr


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 deploy.py deploy/attestation")
        exit(1)

    if sys.argv[1] == "deploy":
        addr = depoly_contract(0)
        print("Contract Address: ", addr)

    elif sys.argv[1] == "attestation":
        if not os.path.exists("/dev/attestation/quote"):
            print("Cannot find `/dev/attestation/quote`; "
                  "are you running under SGX, with remote attestation enabled?")
            sys.exit(1)

        with open('/dev/attestation/attestation_type') as f:
            print(f"attestation type: {f.read()}")

        with open("/dev/attestation/user_report_data", "wb") as f:
            f.write(account.address.encode())

        with open("/dev/attestation/quote", "rb") as f:
            quote = f.read()

        print(f"quote: {quote.hex()}")
