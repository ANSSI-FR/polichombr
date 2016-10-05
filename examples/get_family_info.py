#!/usr/bin/env python
"""
    Simple script to add families by using the API
"""
import argparse
from poliapi.mainapi import FamilyModule


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get family infos')
    parser.add_argument('names',
                        type=str,
                        nargs='+',
                        help="The families name")

    args = parser.parse_args()

    fapi = FamilyModule()
    for fname in args.names:
        family = fapi.get_family(fname)["family"]
        print "Family name: ", family["name"]
        print "Family ID  : ", family["id"]
        print "Family abstract:", family["abstract"]
        print "Family samples: ", family["samples"]
