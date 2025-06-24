import json
import os

from solcx import install_solc, set_solc_version, get_solcx_install_folder


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), '../config')
CONFIG_PATH = os.environ.get('CONFIG_PATH', DEFAULT_CONFIG_PATH)

DEFAULT_SOURCE_PATH = os.path.join(os.path.dirname(__file__), '../../contract.sol')
SOURCE_PATH = os.environ.get("CONTRACT_SOURCE", "../contract.sol")

SOLC_PATH = os.environ.get("SOLCX_BINARY_PATH", "/usr/bin/solc")

DEFAULT_PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), '../private_key')
PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH', DEFAULT_PRIVATE_KEY_PATH)


with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)

if not os.path.exists(SOLC_PATH):
    install_solc("0.8.28")
    set_solc_version("0.8.28")
    print("solc v0.8.28 loaded successfully")
    SOLC_PATH = f"{get_solcx_install_folder()}/solc-v0.8.28"
