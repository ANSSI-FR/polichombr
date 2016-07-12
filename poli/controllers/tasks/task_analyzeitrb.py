"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        AnalyzeIt task implementation.
"""

import os
import re
import time

from subprocess import Popen

from poli import app
from poli.controllers.task import Task
from poli.controllers.sample import SampleController
from poli.controllers.idaactions import IDAActionsController


class task_analyzeitrb(Task):
    """
    This is a wrapper class for the AnalyzeIt.rb script.
    """
    sid = None
    txt_report = None
    sid = None
    storage_file = None
    tmessage = None

    def __init__(self, sample=None):
        super(task_analyzeitrb, self).__init__()
        self.sid = sample.id
        self.txt_report = ""
        self.storage_file = sample.storage_file
        if "application/x-dosexec" not in sample.mime_type:
            self.is_interrested = False

    def execute(self):
        self.tstart = int(time.time())
        self.tmessage = "ANALYZEITRB TASK %d :: " % (self.sid)
        app.logger.debug(self.tmessage + "EXECUTE")
        self.analyze_it()
        return True

    def apply_result(self):
        sc = SampleController()
        idac = IDAActionsController()
        sample = SampleController.get_by_id(self.sid)
        if sample is None:
            app.logger.error(self.tmessage + "Sample has disappeared...")
            raise IOError
        app.logger.debug(self.tmessage + "APPLY_RESULT")

        # TXT report
        app.logger.info("Starting analysis creation")
        SampleController.create_analysis(
            sample, self.txt_report, "analyzeit", True)

        # MACHOC report: we load the functions, hashes, etc.
        app.logger.info("Starting functions")
        fname = self.storage_file + '.sign'
        functions = []
        if os.path.exists(fname):
            fdata = open(fname, 'rb').read()
            items = fdata.split(";")
            for i in items:
                if ":" in i:
                    subitems = i.split(":")
                    machoc_h = subitems[0].strip()
                    address = subitems[1].strip()
                    functions.append([address, machoc_h, ""])

        # IDA COMMANDS report:
        # update functions list with idc.MakeName() information
        # TODO: also store comments
        app.logger.info("Starting idacommands")
        fname = self.storage_file + '.idacmd'
        if os.path.exists(fname):
            fdata = open(fname, 'rb').read()
            for line in fdata.split("\n"):
                if line.startswith("idc.MakeName::"):
                    items = line.split("::")
                    if len(items) == 3:
                        addr = items[1]
                        name = items[2]
                        if addr.startswith("0x"):
                            addr = addr[2:]
                        for i in functions:
                            if i[0] == addr:
                                i[2] = name
                        name_action = idac.add_name(int(addr, 16), name)
                        SampleController.add_idaaction(sample.id, name_action)
                elif line.startswith("idc.MakeRptCmt::"):
                    items = line.split("::")
                    if len(items) == 3:
                        addr = items[1]
                        value = items[2]
                        if addr.startswith("0x"):
                            addr = addr[2:]
                        try:
                            addr = int(addr, 16)
                        except Exception:
                            continue
                        act = idac.add_comment(addr, value)
                        SampleController.add_idaaction(sample.id, act)
        # Functions: just push the list
        app.logger.info("Storing actions")
        if len(functions) > 0:
            sc.add_multiple_functions(sample, functions)

        # global machoc match
        app.logger.info("Matching actions")
        sc.match_by_machoc80(sample)
        app.logger.debug(self.tmessage + "END - TIME %i" %
                         (int(time.time()) - self.tstart))

        return True

    def analyze_it(self):
        """
        Wrapper for the ruby analysis script.
        Executes and get results from files.
        """
        FNULL = open(os.devnull, 'w')
        args = ['ruby', 'analysis_tools/AnalyzeIt.rb', self.storage_file]
        proc = Popen(args, stdin=FNULL, stdout=FNULL, stderr=FNULL)
        proc.wait()
        FNULL.close()

        # TEXT report, just UTF-8 decode/parsing
        fname = self.storage_file + '.txt'
        if os.path.exists(fname):
            data = open(fname, 'rb').read()
            self.txt_report = re.sub(r'[^\x00-\x7F]', '', data).decode('utf-8')

        return True
