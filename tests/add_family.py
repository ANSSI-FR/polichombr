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

parser.add_argument('-p',
                    type=int,
                    default='5000',
                    help='The server port')

parser.add_argument('-u',
                    type=str,
                    default="http://localhost",
                    help="Polichombr's url")

args = parser.parse_args()

parent = args.parent


for fname in args.names:
    fam = {'name': fname, 'parent': parent}
    r = requests.post(args.u+':'+str(args.p) + '/api/1.0/family/',
                      json=fam)
    print r.json()
