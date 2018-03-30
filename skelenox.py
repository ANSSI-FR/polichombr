"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018
"""

import os
import logging

import idaapi

from skelenox_plugin.core import SkelCore


g_logger = logging.getLogger(__name__)
for h in g_logger.handlers:
    g_logger.removeHandler(h)

g_logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
format_str = '[%(asctime)s] [%(levelname)s] [%(threadName)s]: %(message)s'
formatter = logging.Formatter(format_str, datefmt='%d/%m/%Y %I:%M:%S')
handler.setFormatter(formatter)
g_logger.addHandler(handler)


def launch_skelenox():
    """
        Create the instance and launch it
    """
    configname = os.path.dirname(__file__) + "/" + "skelsettings.json"
    skelenox = SkelCore(configname)
    skelenox.run()
    return skelenox


def PLUGIN_ENTRY():
    """
        IDAPython plugin wrapper
    """
    idaapi.auto_wait()
    return SkelenoxPlugin()


class SkelenoxPlugin(idaapi.plugin_t):
    """
        Classic IDAPython plugin
    """

    PLUGIN_NAME = "Skelenox"

    flags = idaapi.PLUGIN_UNL
    comment = "Skelenox"
    help = "Polichombr collaboration agent"
    wanted_name = "Skelenox"
    wanted_hotkey = "Ctrl-F4"
    skel_object = None

    def init(self):
        """
        IDA plugin init
        """
        self.icon_id = 0
        self.skel_object = None

        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        self.skel_object = launch_skelenox()
        return

    def term(self):
        if self.skel_object is not None:
            self.skel_object.end_skelenox()


if __name__ == '__main__':
    # run as a script
    idaapi.auto_wait()
    if "skel" in globals() and skel is not None:
        g_logger.info("Previous instance found, killing it")
        skel.end_skelenox()
    skel = launch_skelenox()
