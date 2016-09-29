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

parser.add_argument('--tlp', type=int,
        help="The TLP level, can be from 1 to 5, 1=TLPWHITE / 5=TLPBLACK")

args = parser.parse_args()

parent = args.parent


for fname in args.names:
    fam = {'name': fname, 'parent': parent, 'tlp_level': args.tlp}
    r = requests.post("http://localhost:5000/api/1.0/family/",
                      json=fam)
    print r.json()
