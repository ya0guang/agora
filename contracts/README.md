# Smart Contract of PCC TEE

Python interface of smart contract

## Installation

`python3` is required to execute the script, and the following libraries are necessary:

```
argparse
requests
web3
```

Run the following command to install libraries via `pip`:
```shell
pip install argparse requests web3
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
- Smart Contract (`0xd17f3F14D8D3Bb6da1f3f769048c365953b7bB6D`)

### Publish

Publish the bug bounty task with the following paramaters:

- `file hash`: `0653c7e992d7aad40cb2635738b870e4c154afb346340d02c797d490dd52d5ff`
- `file name`: `test_file`
- `expire timestamp`: `1683997279`
- `constraints`: `['test.txt', 'test.txt']`

```shell
$ python3 main.py publish 0xd17f3F14D8D3Bb6da1f3f769048c365953b7bB6D  0653c7e992d7aad40cb2635738b870e4c154afb346340d02c797d490dd52d5ff test_file 1683997279 test.txt test.txt
Transaction 0x03067bb882644e3beb201bd2d5ebed891456b7278c6e9a7f31f5e2b3672ed2e8 is mined in block: 8358350
View transaction on https://goerli.etherscan.io/tx/0x03067bb882644e3beb201bd2d5ebed891456b7278c6e9a7f31f5e2b3672ed2e8
```

### Check

Check and remove the bug bounty task (whose file hash is `0653c7e992d7aad40cb2635738b870e4c154afb346340d02c797d490dd52d5ff`).

```shell
$ python3 main.py check 0xd17f3F14D8D3Bb6da1f3f769048c365953b7bB6D  0653c7e992d7aad40cb2635738b870e4c154afb346340d02c797d490dd52d5ff
Transaction 0xd64c32325780293682c2e73525ddceaa44de0279791d0a3471db624b7652b426 is mined in block: 8358382
View transaction on https://goerli.etherscan.io/tx/0xd64c32325780293682c2e73525ddceaa44de0279791d0a3471db624b7652b426
```
