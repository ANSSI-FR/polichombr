"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR

    Description:
        Login using an API key,
        and show the resulting token
"""

import argparse
import requests


def get_auth_token(key):
    """
        Get a token from the backend
    """
    json_data = dict(api_key=str(key))
    req = requests.post('http://localhost:5000/api/1.0/auth_token/',
                        json=json_data)

    return req.json()["token"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auth token example")
    parser.add_argument("api_key", type=str, help="Your API key")
    args = parser.parse_args()
    token = get_auth_token(args.api_key)
    print("Your token: %s" % token)
