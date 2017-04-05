#!/usr/bin/env python
"""
    This is an example scripts that creates new yara rules in the backend

    This file is part of Polichombr

        (c) ANSSI-FR 2016
"""

import argparse

from poliapi.mainapi import YaraModule


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add yaras to Polichombr")
    parser.add_argument('rule', help='the rule file')
    parser.add_argument('name', help='the rule name')
    parser.add_argument('--tlp', type=int,
                        default=2,
                        help="The TLP level, can be from 1 to 5, 1=TLPWHITE / 5=TLPBLACK")
    args = parser.parse_args()
    yara_api = YaraModule()
    rule = open(args.rule).read()
    rule_id = yara_api.create_yara(args.name, rule, args.tlp)
    print "Created rule %s with id %d" % (args.name, rule_id)
