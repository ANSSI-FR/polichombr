"""
    This file is part of Polichombr
        (c) 2018 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    Description:
        Upload information and sample contained in an IDA database
        to a polichombr instance

    Dependencies:
        This script uses the python-idb tool from https://github.com/williballenthin/python-idb
"""


import argparse
import os
import logging

import idb
import hashlib

from poliapi.mainapi import TLP_AMBER, SampleModule
from poliapi.idaactions import IDAActionModule

handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
g_logger = logging.getLogger(__name__)
log_format = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(log_format)
g_logger.addHandler(handler)
g_logger.setLevel(logging.DEBUG)


class IDBUploader(object):
    def __init__(self, idbpath):
        """
            Init the uploader
        """
        assert os.path.exists(idbpath)
        self.idbpath = idbpath
        self.sm = SampleModule()
        self.idaapi = IDAActionModule()
        self.sid = None

    def upload_sample(self):
        """
            Check for sample existence and its hash,
            then uploads it
        """
        if not os.path.exists(self.sample):
            g_logger.exception("The corresponding sample does not exists!")
            raise IOError
        sample_md5 = hashlib.md5(open(self.sample).read()).hexdigest()
        if sample_md5 != self.md5:
            g_logger.exception("Sample hash mismatch")
            raise IOError

        self.sid = self.sm.send_sample(self.sample, TLP_AMBER)
        g_logger.info("Successfully uploaded sample %s -> %d",
                      self.md5,
                      self.sid)

    def send_names(self):
        with idb.from_file(self.idbpath) as db:
            api = idb.IDAPython(db)
            for ea in api.idautils.Functions():
                mflags = api.idc.GetFlags(ea)

                # Check if it is a dummy name
                # TODO: check for automatic names
                if not api.ida_bytes.has_dummy_name(mflags):
                    fname = api.idc.GetFunctionName(ea)
                    self.idaapi.send_name(self.sid, fname, ea)
                    g_logger.debug("Sent name: 0x%x:%s", ea, fname)

    def print_idb_infos(self):
        g_logger.info("Uploading information from IDB %s", self.idbpath)
        with idb.from_file(self.idbpath) as db:
            root = idb.analysis.Root(db)
            g_logger.debug("Sample MD5: %s", root.md5)
            self.md5 = root.md5
            g_logger.debug("Database version %d created on %s opened %d times",
                           root.version,
                           root.created,
                           root.open_count)
            nn = idb.netnode.Netnode(db, "Root Node")
            self.sample = nn.valstr()
            g_logger.debug("Original filename: %s", self.sample)

    def upload_all(self):
        self.print_idb_infos()
        self.upload_sample()
        self.send_names()
        #self.upload_comments()


def get_args():
    parser = argparse.ArgumentParser(
                      description="Upload IDB informations to Polichombr")
    parser.add_argument("idb", nargs="+", help="IDB files to upload")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_args()
    for idb_path in args.idb:
        uploader = IDBUploader(idb_path)
        uploader.upload_all()
