import json
import os


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../config.json')
CONFIG_PATH = os.environ.get('CONFIG_PATH', DEFAULT_CONFIG_PATH)

DEFAULT_SOURCE_PATH = os.path.join(os.path.dirname(__file__), '../../contract.sol')
SOURCE_PATH = os.environ.get("CONTRACT_SOURCE", "../contract.sol")

SOLC_PATH = os.environ.get("SOLCX_BINARY_PATH", "/usr/bin/solc")

DEFAULT_PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), '../private_key')
PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH', DEFAULT_PRIVATE_KEY_PATH)


with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)


