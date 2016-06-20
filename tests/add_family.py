#!/usr/bin/env python
"""
    Simple script to add families by using the API
"""
import argparse
import requests

parser = argparse.ArgumentParser(description='Add a family')
parser.add_argument('names',
                    type=str,
                    nargs='+',
                    help="The new family name")

parser.add_argument('--parent',
                    type=str,
                    help='The parent family name')

args = parser.parse_args()

parent = args.parent


for fname in args.names:
    fam = {'name': fname, 'parent': parent}
    r = requests.post("http://localhost:5000/api/1.0/family/",
                      json=fam)
    print r.json()
