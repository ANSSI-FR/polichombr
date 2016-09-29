#!/usr/bin/env python

import argparse
import requests


def send_sample(sample="", family=None, tlp=None):
    data = open(sample, 'rb').read()

    files = {'file': data}
    payload = {'filename': sample}
    print tlp
    print type(tlp)
    if tlp is not None:
        payload['tlp_level'] = tlp

    if family is not None:
        r = requests.get("http://localhost:5000/api/1.0/family/"+family)
        res = r.json()
        if res["family"] is None:
            print "[!] Error : the family does not exist..."
            return False

    r = requests.post("http://localhost:5000/api/1.0/samples/",
                      files=files, data=payload)
    print r.status_code
    print r.json()
    res = r.json()
    sid = res['sample']['id']
    print "Uploaded sample ID : ", sid
    if args.family is not None:
        fam = {'family_name': args.family}
        r = requests.post("http://localhost:5000/api/1.0/samples/" +
                          str(sid) +
                          '/families/',
                          json=fam)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send sample via the API")
    parser.add_argument('samples', help='the samples files', nargs='+')
    parser.add_argument('--family', help='associated family')
    parser.add_argument('--tlp', type=int,
            help="The TLP level, can be from 1 to 5, 1=TLPWHITE / 5=TLPBLACK")
    args = parser.parse_args()
    for sample in args.samples:
        send_sample(sample, args.family, args.tlp)
