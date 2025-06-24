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
# reutrn: [{'IpfsHash': '', 'PinSize': ''}]
def upload_constraints(constraints):
    payload = {
        "pinataContent": constraints
    }
    headers = {
        "Authorization": f"Bearer {CONFIG['PINATA_JWT']}",
        "Content-Type": "application/json"
    }
    response = requests.post(CONFIG['ENDPOINT'] + '/pinning/pinJSONToIPFS', json=payload, headers=headers)
    return response.json()


# get constraint from gateway
def get_from_gateway(hash):
    for gateway in PUBLIC_GATEWAYS:
        url = f"{gateway}/ipfs/{hash}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    return None
