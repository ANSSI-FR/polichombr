#!/usr/bin/env python

import argparse
import requests


def send_sample(sample="", family=None):
    data = open(sample, 'rb').read()

    files = {'file': data}
    payload = {'filename': sample}

    if family is not None:
        r = requests.get("http://localhost:5000/api/1.0/family/"+family)
        res = r.json()
        if res["family"] is None:
            print "[!] Error : the family does not exist..."
            return False

    r = requests.post("http://localhost:5000/api/1.0/samples/",
                      files=files, data=payload)
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
    args = parser.parse_args()
    for sample in args.samples:
        send_sample(sample, args.family)
