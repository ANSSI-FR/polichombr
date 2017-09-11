"""
    This file is part of Polichombr
    (c) 2017 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    This file contains the module to use the external polichombr REST API.
"""

import argparse
from poliapi.mainapi import FamilyModule


class MainParser(object):
    parser = None
    action_parser = None

    server = None
    server_port = None
    check_certificate = None
    base_uri = None

    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--zoby', default=234)
        self.parser.add_argument('--server', default="127.0.0.1",
                                 dest=self.server,
                                 help="The server domain/IP")
        self.parser.add_argument('--port', default=5000,
                                 help="The server's port")
        # self.parser.add_argument('--check-certificate', default=True,
        # dest=self.check_certificate,
        # help="Option to check SSL certificate status")

        self.action_parser = self.parser.add_subparsers(
            help='Available subcommands')


class FamilyParser(MainParser):
    """
        Family endpoint
    """

    def __init__(self):
        super(FamilyModule, self).__init__()
        create_parser = self.action_parser.add_parser(
            'create', help="Create a new family")
        create_parser.add_argument("name", help="The family name")
        create_parser.add_argument("--parent", help="The parent family")

        delete_parser = self.action_parser.add_parser(
            'delete', help="Delete a family")
        delete_parser.add_argument("name", help="The family name")

        args = self.parser.parse_args()
        print args
        self.setup_default_args(args)

    def create_family(self):
        pass
