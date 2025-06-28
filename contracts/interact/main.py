import argparse

from utils.interact import *


def parse_args():
    parser = argparse.ArgumentParser(description='Python interface for the smart contract')
    subparsers = parser.add_subparsers(dest='command')

    # init subparser
    parser_init = subparsers.add_parser('init', help='initialize the private key')
    parser_init.add_argument('-f', '--force', help='force regenerate private key', action='store_true')
    # publish task subparser
    parser_publish = subparsers.add_parser('publish', help='publish bug bounty task')
    parser_publish.add_argument('contract_address', type=str, help='contract address')
    parser_publish.add_argument('hash', type=str, help='file hash')
    parser_publish.add_argument('name', type=str, help='file name')
    parser_publish.add_argument('constraints', type=str, nargs='*', help='constraint pathes')
    # verify bug subparser
    parser_verify = subparsers.add_parser('verify', help='verify and update bug bounty task')
    parser_verify.add_argument('contract_address', type=str, help='contract address')
    parser_verify.add_argument('hash', type=str, help='file hash')
    # bug confirm attestation subparser
    parser_confirm = subparsers.add_parser('confirm', help='confirm bug bounty task and generate attestation')
    parser_confirm.add_argument('hash', type=str, help='file hash')
    parser_confirm.add_argument('address', type=str, help='bug bounty hunter address')
    # parse args
    args = parser.parse_args()

    return args


def main(args):
    if args.command == 'init':
        address, exists = init_private_key(args.force)
        if exists:
            print('Private key exists! Address is {}'.format(address))
        else:
            print('Generate successfully! Address is {}'.format(address))

        claim_address()
    elif args.command == 'publish':
        receipt = publish_task_util(args.contract_address, args.hash, args.name, args.constraints)
        print_receipt(receipt)
    elif args.command == 'verify':
        receipt = verify_bug_util(args.contract_address, args.hash)
        print_receipt(receipt)
    elif args.command == 'confirm':
        claim_bug(args.hash, args.address)
    else:
        print('Invalid command')


if __name__ == '__main__':
    args = parse_args()
    main(args)
