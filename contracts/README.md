# Artifacts for BTM (Smart Contracts and Basic Rewards)

## Installation

`python3` is required to execute the script, and the following libraries are necessary:

```
argparse
requests
web3
py-solc-x
seaborn
scipy
matplotlib
```

Run the following command to install libraries via `pip`:

```sh
pip install argparse requests web3 py-solc-x seaborn scipy matplotlib
```

## BTM Cost

To reproduce Figure 8, run the following command. The output will be saved as `btm-cost.pdf`:

```sh
python3 btm-cost.py
```

## Smart Contract Cost

We have deployed an instance of the BTM smart contract on the Ethereum Sepolia testnet: [0x52226034eed249f67ebecb2252b193de4f72e856](https://sepolia.etherscan.io/address/0x52226034eed249f67ebecb2252b193de4f72e856).

To simplify the evaluation of our artifacts, we suggest checking the gas costs directly from the historical transactions we sent, as they are publicly available due to the transparent nature of blockchain.

Note: Reviewers can click "Click to show more" on the webpage provided by the blockchain explorer to view the gas usage, which is shown under the "Gas Limit & Usage by Txn" column.

- `deploying` - [0x5f014e3df73fe7ddb4ef751f775d60e640fe3eb7b98fab403d06ff40958179a4](https://sepolia.etherscan.io/tx/0x5f014e3df73fe7ddb4ef751f775d60e640fe3eb7b98fab403d06ff40958179a4)
- `publishing a task bundle` - [0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0](https://sepolia.etherscan.io/tx/0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0)
- `recording the verification result` - [0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a](https://sepolia.etherscan.io/tx/0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a)
- `verifying an ECDSA attestation quote` - [0xa1faf3f9715ee6be2861b449b5b7f36422f7811ef9f10175260aaa1ad5484808](https://sepolia.etherscan.io/tx/0xa1faf3f9715ee6be2861b449b5b7f36422f7811ef9f10175260aaa1ad5484808)


<details>
<summary>If you are interested, click to view smart contract usage instructions.</summary>

## Usage

Python interface includes the following commands for proof checkers and bug verifiers to publish and check the bug bounty task, and for bug hunters to submit their bug attestations.

### init

Initialize the private key, using `-f`/`--force` to force regenerate private key.

### publish

Publish the bug bounty task with the following paramaters:
- `contract_address`: contract address
- `hash`: binary hash
- `name`: file name
- `constraints` constraint pathes

### check

Check and remove the bug bounty task with the file hash:
- `contract_address`: contract address
- `hash`: constraints hash

### submit

Submit the attestation of the bug bounty task with the file hash and attestation:

- `contract_address`: contract address
- `hash`: constraints hash
- `attestation_path`: attestation path

## Demo

### Address

- Proof Checker (`0x23D70f3950985E9A89A10cbf164F9274B99351bB`)
- Bug Verifier (`0x23D70f3950985E9A89A10cbf164F9274B99351bB`)
- Smart Contract (`0x52226034EeD249f67EbECb2252B193de4f72e856`)

### Publish

Publish the bug bounty task with the following paramaters:

- `file hash`: `e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba`
- `file name`: `test_file`
- `constraints`: `['test.txt', 'test.txt']`

```sh
$ python3 main.py publish 0x52226034EeD249f67EbECb2252B193de4f72e856 e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba test_file test.txt
Transaction 0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0 is mined in block: 
7722512
View transaction on https://sepolia.etherscan.io/tx/0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0
```

### Check

Check and remove the bug bounty task (whose file hash is `e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba`).

```sh
$ python3 main.py verify 0x52226034EeD249f67EbECb2252B193de4f72e856 e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba
Transaction 0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a is mined in block: 7722519
View transaction on https://sepolia.etherscan.io/tx/0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a
```
</details>