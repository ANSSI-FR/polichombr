import requests
import argparse
import sys


def get_auth_token(key):
    json_data = dict(api_key=str(key))
    req = requests.post('http://localhost:5000/api/1.0/get_auth_token/',
                        json=json_data)

    return req.json()["token"]


def get_protected_api(token):

    for i in xrange(0x20):
        req = requests.get('http://localhost:5000/api/1.0/families/',
                           headers={'X-Api-Key': token})

        print req.status_code


if __name__ == "__main__":
    token = get_auth_token(sys.argv[1])
    get_protected_api(token)
