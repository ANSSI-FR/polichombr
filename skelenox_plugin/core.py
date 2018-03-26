"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        This is the core of skelenox
"""

import time
import atexit
import logging

import idc
import idaapi
import idautils

from .utils import SkelUtils
from .sync_agent import SkelSyncAgent
from .config import SkelConfig
from .connection import SkelIDAConnection
from .hooks import SkelHooks
from .ui import SkelUI

logger = logging.getLogger(__name__)


class SkelCore(object):
    """
        This is the main class for skelenox.
        It handles startup, manage agents, connections and so on.
    """
    crit_backup_file = None
    backup_file = None
    last_saved = None
    skel_conn = None
    skel_settings = None
    settings_filename = ""
    skel_hooks = None
    skel_sync_agent = None
    skel_ui = None

    def __init__(self, settings_filename):
        """
            Prepare for execution
        """
        SkelUtils.header()

        logger.info("[+] Init Skelenox")

        # Load settings
        self.skel_settings = SkelConfig(settings_filename)

        self.skel_conn = SkelIDAConnection(self.skel_settings)

        # If having 3 idbs in your current path bother you, change this
        self.crit_backup_file = idc.get_idb_path()[:-4] + "_backup_preskel.idb"
        self.backup_file = idc.get_idb_path()[:-4] + "_backup.idb"

        atexit.register(self.end_skelenox)

        logger.info(
            "Backuping IDB before any intervention (_backup_preskel)")
        idc.save_database(self.crit_backup_file, idaapi.DBFL_TEMP)
        logger.info("Creating regular backup file IDB (_backup)")
        idc.save_database(self.backup_file, idaapi.DBFL_TEMP)
        self.last_saved = time.time()

        if self.skel_hooks is not None:
            self.skel_hooks.cleanup_hooks()

        if not self.skel_conn.get_online():
            logger.error("Cannot get online =(")

        # Synchronize the sample
        self.skel_sync_agent = SkelSyncAgent()
        self.skel_sync_agent.setup_config(settings_filename)

        # setup hooks
        self.skel_hooks = SkelHooks(self.skel_conn)

        # setup UI
        if self.skel_settings.use_ui:
            self.skel_ui = SkelUI(settings_filename)

        # setup skelenox terminator
        self.setup_terminator()

        logger.info("Skelenox init finished")

    def send_names(self):
        """
            Used to send all the names to the server.
            Usecase: Previously analyzed IDB
        """
        for head in idautils.Names():
            if not idaapi.has_dummy_name(idaapi.get_flags(head[0])):
                self.skel_conn.push_name(head[0], head[1])

    def send_comments(self):
        """
            Initial sync of comments
        """
        for head in idautils.Heads():
            cmt = SkelUtils.get_comment(head)
            if cmt:
                self.skel_conn.push_comment(head, cmt)

    def run(self):
        """
            Launch the hooks!
        """
        idaapi.disable_script_timeout()
        init_sync = 0
        if idc.ask_yn(init_sync,
                      "Do you want to push your names and comments") == 1:
            self.send_names()
            self.send_comments()

        if self.skel_settings.use_ui:
            self.skel_ui.Show()
        self.skel_sync_agent.start()
        self.skel_hooks.hook()

    def setup_terminator(self):
        """
            Register an exit callback
        """
        def end_notify_callback(nw_arg):
            """
                Callback that destroys the object when exiting
            """
            logger.debug("Being notified of exiting DB")
            self.end_skelenox()
        idaapi.notify_when(idaapi.NW_CLOSEIDB | idaapi.NW_TERMIDA,
                           end_notify_callback)

    def end_skelenox(self):
        """
            cleanup
        """
        self.skel_conn.close_connection()
        if self.skel_hooks is not None:
            self.skel_hooks.cleanup_hooks()

        self.skel_sync_agent.kill()
        self.skel_sync_agent.skel_conn.close_connection()
        self.skel_sync_agent.join()
        if self.skel_settings.use_ui:
            self.skel_ui.Close()

        logger.info("Skelenox terminated")
