#!usr/bin/env python
"""
    This script is used to send samples to the API

    This file is part of Polichombr

        (c) ANSSI-FR 2018
"""

import argparse

from poliapi.mainapi import SampleModule, FamilyModule


def send_sample(sample="", family=None, tlp=None, api_key=""):
    """
        Send a sample using the SampleModule API
    """
    sapi = SampleModule(api_key=api_key)
    if family is not None:
        fapi = FamilyModule(api_key=api_key)
        answer = fapi.get_family(family)
        if answer["family"] is None:
            print("[!] Error : the family does not exist...")
            return False
    sid = sapi.send_sample(sample, tlp)

    print("Uploaded sample ID : %d" % sid)
    if family is not None:
        answer = sapi.assign_to_family(sid, family)
        if not answer['result']:
            print("Cannot affect sample to family")
            return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send sample via the API")
    parser.add_argument('api_key', type=str, help="Your API key")
    parser.add_argument('samples', help='the samples files', nargs='+')
    parser.add_argument('--family', help='associated family')
    parser.add_argument('--tlp', type=int,
                        help="The TLP level,\
                              can be from 1 to 5,\
                              1=TLPWHITE / 5=TLPBLACK")
    args = parser.parse_args()
    for sample in args.samples:
        send_sample(sample, args.family, args.tlp, args.api_key)
