# Smart Contract of PCC TEE

Python interface of smart contract

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

```shell
pip install argparse requests web3 py-solc-x seaborn scipy matplotlib
```

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

```shell
$ python3 main.py publish 0x52226034EeD249f67EbECb2252B193de4f72e856 e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba test_file test.txt
Transaction 0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0 is mined in block: 
7722512
View transaction on https://sepolia.etherscan.io/tx/0x7e5dee9ac616dfdb8c0ab1f196ba4230dee8a22c15470ddf1eeddcca50f4add0
```

### Check

Check and remove the bug bounty task (whose file hash is `e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba`).

```shell
$ python3 main.py verify 0x52226034EeD249f67EbECb2252B193de4f72e856 e6f265e5894c2687008c7400a188cc2fe06224a0cacc7e12339c9a71a5e17eba
Transaction 0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a is mined in block: 7722519
View transaction on https://sepolia.etherscan.io/tx/0xf9d9ca1ea3b6a18dd140cd19d3b4eb55af53854b640c8cec9487583dcc38a43a
```
