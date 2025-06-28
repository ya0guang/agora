import hashlib
import json
import requests

from .config import CONFIG

# public gateways
PUBLIC_GATEWAYS = [
    "https://ipfs.io",
    "https://gateway.ipfs.io",
    "https://cloudflare-ipfs.com"
]


# upload constraints to IPFS
# reutrn: [{'Name': '', 'Hash': '', 'Size': ''}]
def upload_constraints(constraints):
    response = requests.post(CONFIG['ENDPOINT'] + '/api/v0/add', files=constraints, auth=(CONFIG['PROJECT_ID'], CONFIG['PROJECT_SECRET']))
    items = [json.loads(item) for item in response.text.split("\n") if item != '']
    return items


# check constraint on gateway
def check_proof_on_gateway(constraint, hash):
    constraint_md5sum = hashlib.md5(constraint.encode()).hexdigest()

    flag = False

    for gateway in PUBLIC_GATEWAYS:
        url = f"{gateway}/ipfs/{hash}"
        response = requests.get(url)
        if response.status_code == 200:
            flag = True
            response_md5sum = hashlib.md5(response.text.encode()).hexdigest()
            if response_md5sum != constraint_md5sum:
                return False

    return flag
