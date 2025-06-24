# Artifacts for BTM (Smart Contracts and Basic Rewards)

## Installation

`python3` is required to execute the script, and the following libraries are necessary:

- seaborn
- scipy
- matplotlib

Run the following command to install libraries via `pip`:

```sh
pip install seaborn scipy matplotlib
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

The instructions for installation and usage of smart contracts are available in [README.md](./README.md).
