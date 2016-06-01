#!/usr/bin/env python
"""
    Simple script to add families by using the API
"""
import argparse
import requests

parser = argparse.ArgumentParser(description='Get family infos')
parser.add_argument('names',
                    type=str,
                    nargs='+',
                    help="The families name")

args = parser.parse_args()

for fname in args.names:
    r = requests.get("http://localhost:5000/api/1.0/family/"+fname)
    print r.json()
