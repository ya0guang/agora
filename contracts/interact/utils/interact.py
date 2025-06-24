import os
import sys

from .blockchain import *
from .config import PRIVATE_KEY_PATH
from .ipfs import *


def check_hash(hash_bytes):
    if hash_bytes.startswith('0x'):
        hash_bytes = hash_bytes[2:]
    if len(hash_bytes) != 64:
        print('Invalid hash')
        exit(0)
    return bytes.fromhex(hash_bytes)


def init_private_key(force):
    exists = False
    if not os.path.exists(PRIVATE_KEY_PATH) or force:
        private_key, address = generate_private_key()
        with open(PRIVATE_KEY_PATH, 'w') as f:
            f.write(private_key)
    else:
        with open(PRIVATE_KEY_PATH, 'r') as f:
            private_key = f.read()
        address = w3.eth.account.from_key(private_key).address
        exists = True
    return address, exists


def check_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        print('Please initialize the private key first!')
        exit(0)

    with open(PRIVATE_KEY_PATH, 'r') as f:
        private_key = f.read()

    return private_key


def check_TEE():
    if not os.path.exists("/dev/attestation/quote"):
        print("Cannot find `/dev/attestation/quote`; "
                  "are you running under SGX, with remote attestation enabled?")
        sys.exit(1)


def claim_address():
    check_TEE()
    with open('/dev/attestation/attestation_type') as f:
        print(f"attestation type: {f.read()}")

    address, exists = init_private_key(False)

    with open("/dev/attestation/user_report_data", "wb") as f:
        f.write(address.encode())

    with open("/dev/attestation/quote", "rb") as f:
        quote = f.read()

    print(f"quote: {quote.hex()}")


def claim_bug(file_hash, address):
    check_TEE()

    with open('/dev/attestation/attestation_type') as f:
        print(f"attestation type: {f.read()}")


    with open("/dev/attestation/user_report_data", "wb") as f:
        f.write(file_hash.encode())
        f.write(address.encode())

    with open("/dev/attestation/quote", "rb") as f:
        quote = f.read()

    print(f"quote: {quote.hex()}")


def upload_to_ipfs_and_check(file_pathes):
    # read file content
    file_content = {}
    for file_path in file_pathes:
        if not os.path.exists(file_path):
            print('file {} does not exist'.format(file_path))
            exit(0)

        file_name = os.path.basename(file_path)
        
        with open(file_path, 'r') as f:
            file_content[file_name] = f.read()
    
    # upload to ipfs
    ipfs_res = upload_constraints(file_content)
    print(f'Upload to ipfs successfully! Hash: {ipfs_res["IpfsHash"]}')

    # check file content
    file_content_on_ipfs = get_from_gateway(ipfs_res['IpfsHash'])
    for file_name, content in file_content.items():
        if file_name not in file_content_on_ipfs:
            print('File {} is not uploaded'.format(file_name))
            exit(0)

        if content != file_content_on_ipfs[file_name]:
            print('File {} content is not same'.format(file_name))
            exit(0)

    return [ipfs_res['IpfsHash']]


def publish_task_util(contract_addr, file_hash, file_name, constraints):
    private_key = check_private_key()
    # file hash
    file_hash = check_hash(file_hash)
    # upload and check constraints
    constraint_hashes = upload_to_ipfs_and_check(constraints)
    return publish_task(private_key, contract_addr, file_hash, file_name, constraint_hashes)


def verify_bug_util(contract_addr, file_hash):
    private_key = check_private_key()
    file_hash = check_hash(file_hash)
    return verify_bug(private_key, contract_addr, file_hash)
