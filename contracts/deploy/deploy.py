import json
import os
import sys

from solcx import compile_source, set_solc_version, install_solc, get_solcx_install_folder
from web3 import Web3


BASE = os.path.dirname(os.path.abspath(__file__))

CONFIG = os.path.join(BASE, "config")
NAME = "BugBountyPlatform"

source_path = os.environ.get("CONTRACT_SOURCE", "../contract.sol")
solc_path = os.environ.get("SOLCX_BINARY_PATH", "/usr/bin/solc")


with open(CONFIG, "r") as f:
    config = json.load(f)

# init web3
w3 = Web3(Web3.HTTPProvider(config["provider"]))
# init account
account = w3.eth.account.from_key(config["privateKey"])


# install solc
def check_solc():
    if not os.path.exists(solc_path):
        print(f"Cannot find solc at {solc_path}, install it first")
        try:
            install_solc("0.8.28")
            set_solc_version("0.8.28")
            print("solc installed successfully")
            return f"{get_solcx_install_folder()}/solc-v0.8.28"

        except Exception as err:
            print(f"Failed to install solc: {err}")
            sys.exit(1)
    else:
        return solc_path


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

    constructor = instance.constructor(
        config["ProofCheckers"],
        config["BugVerifiers"],
        config["V3QuoteVerifier"],
        config["V4QuoteVerifier"],
        config["BugVerifier_MRENCLAVE"]
    )

    constructor_tx = constructor.build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'value': w3.to_wei(value, 'ether'),
        'gasPrice': w3.eth.gas_price
    })

    signed_tx = account.sign_transaction(constructor_tx)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"Deploy Successfully! Transaction Hash: 0x{tx_hash.hex()}")
    except Exception as err:
        raise err

    contract_addr = get_contract_addr(tx_hash)
    return contract_addr


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 deploy.py deploy/attestation")
        exit(1)

    if sys.argv[1] == "deploy":
        solc_path = check_solc()
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
