"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Implements a synchronization mechanism
        between the database and the server
"""

import threading
import datetime
import logging

import idaapi

from .config import SkelConfig
from .utils import SkelUtils
from .connection import SkelIDAConnection

logger = logging.getLogger(__name__)


class SkelSyncAgent(threading.Thread):
    """
        Agent that pulls the server regularly for new infos
    """
    skel_conn = None
    skel_settings = None
    last_timestamp = None
    update_event = None
    kill_event = None
    timer_setup_flag = None
    delay = None

    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, name=self.__class__.__name__,
                                  args=args, kwargs=kwargs)
        self.update_event = threading.Event()
        self.kill_event = threading.Event()
        self.last_timestamp = datetime.datetime.fromtimestamp(0)
        logger.debug("SyncAgent initialized")
        self.timer_setup_flag = False
        self.delay = 1000

    def setup_config(self, settings_filename):
        """
            Initialize connection in the new thread
        """
        self.skel_settings = SkelConfig(settings_filename)
        self.delay = self.skel_settings.sync_frequency
        self.skel_conn = SkelIDAConnection(self.skel_settings)
        self.skel_conn.get_online()

    def update_timestamp(self, timestamp_str):
        """
            Converts the timestamp provided
            and update the last update timestamp
        """
        format_ts = "%Y-%m-%dT%H:%M:%S.%f+00:00"
        timestamp = datetime.datetime.strptime(timestamp_str, format_ts)
        self.last_timestamp = max(self.last_timestamp, timestamp)

    def sync_names(self):
        """
            Get the remote comments and names
        """
        if not self.skel_conn.is_online:
            logger.error("[!] Error, cannot sync while offline")
            return False

        comments = self.skel_conn.get_comments(timestamp=self.last_timestamp)
        names = self.skel_conn.get_names(timestamp=self.last_timestamp)
        for comment in comments:
            SkelUtils.execute_comment(comment)
            self.update_timestamp(comment["timestamp"])

        for name in names:
            SkelUtils.execute_rename(name)
            self.update_timestamp(name["timestamp"])
        return True

    def setup_timer(self):
        """
            Setup an IDA timer to trigger regularly the
            update of data from the server
        """
        def update():
            """
                Triggers the synchronization event
            """
            if not self.update_event.isSet():
                self.update_event.set()
            if self.kill_event.isSet():
                # Unregister the timer if we are killed
                return -1
            return self.delay

        def ts_setup_timer():
            """
                Thread safe wrapper for setting up
                the sync callback
            """
            idaapi.register_timer(self.delay, update)

        if not self.timer_setup_flag:
            idaapi.execute_sync(ts_setup_timer, idaapi.MFF_FAST)
            self.timer_setup_flag = True

    def kill(self):
        """
            Instruct the thread to return
        """
        logger.debug("%s exiting", self.__class__.__name__)
        self.kill_event.set()
        # we don't want to wait until the timeout on the update thread,
        # so unlock the update event too
        self.update_event.set()

    def run(self):
        self.setup_timer()
        while True:
            try:
                self.update_event.wait()
                self.update_event.clear()
                # if we are up, sync names
                if self.kill_event.wait(float(self.delay)/1000):
                    return 0
                self.sync_names()
            except Exception as mye:
                logger.exception(mye)
                break
        return
