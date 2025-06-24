#!/usr/bin/env python3

from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider("https://sepolia.infura.io/v3/df06acebf3db497aa87c4d9ffb0ee6d9"))

print("Testing smart contract on Sepolia network")
print("Contract address: 0x52226034eed249f67ebecb2252b193de4f72e856")

# deployment transaction
deployment_tx_hash = (
    "0x5f014e3df73fe7ddb4ef751f775d60e640fe3eb7b98fab403d06ff40958179a4"
)
deployment_tx = w3.eth.get_transaction(deployment_tx_hash)
print(
    f"Deployment transaction details: {deployment_tx_hash} with gas ({deployment_tx['gas']}) is mined at block {deployment_tx['blockNumber']}"
)
print(f"View more details on https://sepolia.etherscan.io/tx/{deployment_tx_hash}")

# publishing a task (transaction)
print("\nPublishing a task...")
publish_tx_hash = "0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0"
publish_tx = w3.eth.get_transaction(publish_tx_hash)
print(
    f"Publishing transaction details: {publish_tx_hash} with gas ({publish_tx['gas']}) is mined at block {publish_tx['blockNumber']}"
)
print(f"View more details on https://sepolia.etherscan.io/tx/{publish_tx_hash}")

# verifying a bug (transaction)
print("\nVerifying a bug...")
verify_tx_hash = "0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a"
verify_tx = w3.eth.get_transaction(verify_tx_hash)
print(
    f"Verifying transaction details: {verify_tx_hash} with gas ({verify_tx['gas']}) is mined at block {verify_tx['blockNumber']}"
)
print(f"View more details on https://sepolia.etherscan.io/tx/{verify_tx_hash}")


# verifying an ECDSA attestation quote (transaction)
print("\nVerifying an ECDSA attestation quote...")
ecdsa_tx_hash = "0xa1faf3f9715ee6be2861b449b5b7f36422f7811ef9f10175260aaa1ad5484808"
ecdsa_tx = w3.eth.get_transaction(ecdsa_tx_hash)
print(
    f"Verifying ECDSA transaction details: {ecdsa_tx_hash} with gas ({ecdsa_tx['gas']}) is mined at block {ecdsa_tx['blockNumber']}"
)
print(f"View more details on https://sepolia.etherscan.io/tx/{ecdsa_tx_hash}")
