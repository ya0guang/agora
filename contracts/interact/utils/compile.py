from solcx import compile_source

from .config import SOURCE_PATH, SOLC_PATH

NAME = "BugBountyPlatform"

def compile_from_src(source, contract_name):
    compiled_sol = compile_source(source, output_values=["abi", "bin", "bin-runtime"], solc_binary=SOLC_PATH)
    for name, contract in compiled_sol.items():
        if contract_name in name:
            return contract
        
with open(SOURCE_PATH, 'r') as f:
    contract_source = f.read()
    contract = compile_from_src(contract_source, NAME)