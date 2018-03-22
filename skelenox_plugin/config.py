"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        This file manages Skelenox configuration
"""

import os
import idc
import json
import logging

logger = logging.getLogger(__name__)


class SkelConfig(object):
    """
        Config management
    """

    def __init__(self, settings_file):
        filename = settings_file
        self.edit_flag = False

        # Network config
        self.poli_server = ""
        self.poli_port = 80
        self.poli_remote_path = ""
        self.poli_apikey = ""
        self.debug_http = False
        self.sync_frequency = 100

        # UI config
        self.use_ui = True
        self.notepad_font_name = "Courier New"
        self.notepad_font_size = "10"

        # Skelenox general config
        self.save_timeout = 10 * 60

        if os.path.isfile(filename):
            logger.info("Loading settings file")
            self._do_init(filename)
        else:
            logger.warning("Config file not edited, populating default")
            self.populate_default(filename)
            self.not_edited(filename)

    @staticmethod
    def not_edited(filename):
        """
            The user have not edited the settings
        """
        idc.Warning("Please edit the %s file with your settings!" % (filename))
        raise EnvironmentError

    def _do_init(self, filename):
        """
            Loads the settings in JSON file
        """
        with open(filename, 'r') as inputfile:
            raw_data = inputfile.read()
            data = json.loads(raw_data, encoding='ascii')
            if data["edit_flag"] is False:
                self.not_edited(filename)
            else:
                for key in data.keys():
                    setattr(self, key, data[key])

    def populate_default(self, filename):
        """
            Dumps the default value in JSON in the given filename
        """
        data = json.dumps(vars(self), sort_keys=True, indent=4)
        with open(filename, 'w') as outfile:
            outfile.write(data)

    def dump_config(self):
        """
            Simply print the config on screen
        """
        values = {}
        for elem in vars(self).keys():
            values[elem] = vars(self)[elem]
        logger.info(json.dumps(values, sort_keys=True, indent=4))
