"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        AnalyzeIt task implementation.
"""

import os
import re

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
        self.tmessage = "ANALYZEITRB TASK %d :: " % (self.sid)
        self.txt_report = ""
        self.storage_file = sample.storage_file
        if "application/x-dosexec" not in sample.mime_type:
            self.is_interrested = False

    @Task._timer
    def execute(self):
        self.analyze_it()
        return True

    @staticmethod
    def get_addr_data(line):
        """
            Parse a line of idacmd results from analyzeit
        """
        items = line.split('::')
        addr, data = None, None
        if len(items) == 3:
            addr = int(items[1], 16)
            data = items[2].replace('\n', '')
        return addr, data

    def parse_machoc_signatures(self):
        """
            Returns a dict containing the functions and the hashes
        """
        # MACHOC report: we load the functions, hashes, etc.
        app.logger.info("Parsing functions")
        fname = self.storage_file + '.sign'
        functions = {}
        if not os.path.exists(fname):
            return functions
        with open(fname) as infile:
            fdata = infile.read()
            items = fdata.split(";")
            for i in items:
                if ":" in i:
                    subitems = i.split(":")
                    machoc_h = int(subitems[0].strip(), 16)
                    address = int(subitems[1].strip(), 16)
                    functions[address] = dict(machoc=machoc_h, name="")
        return functions

    def parse_ida_cmds(self, sid, functions):
        """
            Parse and add IDA commands dumped by AnalyzeIt,
            and updates the functions names if needed
        """
        idac = IDAActionsController()
        funcs = dict.copy(functions)
        fname = self.storage_file + '.idacmd'
        act = None
        if not os.path.exists(fname):
            return funcs
        with open(fname) as fdata:
            for line in fdata:
                if line.startswith('idc.MakeName'):
                    addr, name = self.get_addr_data(line)
                    try:
                        # update functions list with idc.MakeName() information
                        funcs[addr]['name'] = name
                    except KeyError:
                        app.logger.debug("No function found for %x" % (addr))
                    act = idac.add_name(addr, name)
                elif line.startswith('idc.MakeRptCmt'):
                    addr, cmt = self.get_addr_data(line)
                    act = idac.add_comment(addr, cmt)
                else:
                    app.logger.debug("Unknown IDA command %s" % (line))
                    continue
                SampleController.add_idaaction(sid, act)
        return funcs

    @Task._timer
    def apply_result(self):
        samplecontrol = SampleController()
        sample = SampleController.get_by_id(self.sid)
        if sample is None:
            app.logger.error(self.tmessage + "Sample has disappeared...")
            raise IOError
        app.logger.debug(self.tmessage + "APPLY_RESULT")

        # TXT report
        app.logger.info("Creating new analyzeit report")
        SampleController.create_analysis(
            sample, self.txt_report, "analyzeit", True)

        functions = self.parse_machoc_signatures()

        # IDA COMMANDS report:
        app.logger.info("Parsing idacommands")
        functions = self.parse_ida_cmds(sample.id, functions)

        # Functions: just push the list
        app.logger.info("Storing functions")
        samplecontrol.add_multiple_functions(sample, functions)

        # global machoc match
        app.logger.info("Calculating machoc80 matches")
        samplecontrol.match_by_machoc80(sample)
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
