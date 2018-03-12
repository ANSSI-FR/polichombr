"""
    This file is part of Polichombr
        (c) 2018 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    This file defines how to interact
    with Polichombr's API about IDA actions associated to a sample.
"""

from poliapi.mainapi import MainModule


class IDAActionModule(MainModule):
    """
        Interacts with the IDA Actions API on the server
    """
    def send_name(self, sid, name, address):
        data = {"address": address,
                "name": name}
        endpoint = self.prepare_endpoint(root='samples/' + str(sid) + '/names')
        res = self.post(endpoint, json=data)
        return res["result"]
