#!/usr/bin/env python
"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Get informations about a family
"""

import argparse
from poliapi.mainapi import FamilyModule


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get family infos')
    parser.add_argument('names',
                        type=str,
                        nargs='+',
                        help="The families name")
    parser.add_argument("api_key", type=str, help="Auth API key")

    args = parser.parse_args()

    fapi = FamilyModule(api_key=args.api_key)
    for fname in args.names:
        family = fapi.get_family(fname)["family"]
        print "Family name: ", family["name"]
        print "Family ID  : ", family["id"]
        print "Family abstract:", family["abstract"]
        print "Family samples: ", family["samples"]
