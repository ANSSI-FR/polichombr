"""
    This file is part of Polichombr
        (c) 2018 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    This file contains the module to use the external polichombr REST API.
"""

import logging
import ConfigParser

import requests

TLP_WHITE = 1
TLP_GREEN = 2
TLP_AMBER = 3
TLP_RED = 4
TLP_BLACK = 5

class PoliConfig(object):
    """
        Wrapper to store the config values
    """
    server = None
    server_port = None
    base_uri = None
    api_key = None
    logging_level = None
    config = None

    def __init__(self, filename="poliapi.cfg"):
        parser = ConfigParser.ConfigParser()
        parser.read(filename)
        self.server = parser.get("server", "address")
        self.server_port = parser.get("server", "port")
        self.base_uri = parser.get("server", "base_uri")
        self.api_key = parser.get("user", "api_key")
        self.logging_level = parser.get("logging", "level")


class MainModule(object):
    """
        This module provides the main utils
        that are used by the children classes
    """
    logger = None
    config = None
    auth_token = None

    def __init__(self, configfile="poliapi.cfg"):
        self.config = PoliConfig(configfile)
        self.init_logging()

        self.login()

    def init_logging(self):
        handler = logging.StreamHandler()
        handler.setLevel(self.config.logging_level)
        self.logger = logging.getLogger(__name__)
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(log_format)
        self.logger.addHandler(handler)

    def login(self):
        """
            Initialize the auth token by issuing a call to the API
        """
        data = dict(api_key=self.config.api_key)
        ept = self.prepare_endpoint(root="auth_token")
        token = self.post(ept, json=data)["token"]
        self.auth_token = token

    def post(self, endpoint, **kwargs):
        """
            Wrapper for requests.post
        """
        json_data, data, files = None, None, None
        if 'json' in list(kwargs.keys()):
            json_data = kwargs['json']
        if 'data' in list(kwargs.keys()):
            data = kwargs['data']
        if 'files' in list(kwargs.keys()):
            files = kwargs['files']
        headers = {"X-Api-Key": self.auth_token}
        answer = requests.post(endpoint,
                               json=json_data,
                               data=data,
                               files=files,
                               headers=headers)
        if answer.status_code != 200:
            self.logger.error(
                "Error during post request for endpoint %s", endpoint)
            self.logger.error("Status code was: %d", answer.status_code)
            self.logger.error("error message was: %s", answer.json())
            raise IOError
        return answer.json()

    def get(self, endpoint, args=None):
        """
            Wrapper for requests.get
            @arg args is a dict wich is converted to URL parameters
        """
        headers = {"X-Api-Key": self.auth_token}
        answer = requests.get(endpoint, params=args, headers=headers)
        if answer.status_code != 200:
            if answer.status_code == 404:
                self.logger.error(
                    "endpoint %s or resource not found", endpoint)
                self.logger.error(
                    "error description was: %s",
                    answer.json()["error_description"])
                return None
            else:
                self.logger.error(
                    "Error during get request for endpoint %s", endpoint)
                self.logger.error("Status code was %d", answer.status_code)
                self.logger.error("error message was: %s", answer.json())
                raise requests.HTTPError
        return answer.json()

    def prepare_endpoint(self, **kwargs):
        """
            Return a string suitable for requesting the API
        """
        endp = "http://" + self.config.server
        endp += ':' + str(self.config.server_port)
        endp += self.config.base_uri
        if 'root' in list(kwargs.keys()):
            endp += kwargs['root'] + '/'
        return endp


class SampleModule(MainModule):
    """
        Uses the sample endpoint
    """
    sid = None

    def send_sample(self, filename, tlp=TLP_AMBER):
        """
            Upload a sample to the polichombr service
            @arg filename: the sample file to upload
            @arg tlp: the TLP sensitivity of the sample
                This can be from 1 to 5 (TLP WHITE to TLP BLACK)
        """
        try:
            data = open(filename, 'rb').read()
        except IOError:
            self.logger.exception("File does not exists")
            raise IOError

        files = {'file': data}
        payload = {'filename': filename}
        if tlp is not None:
            payload['tlp_level'] = tlp

        endpoint = self.prepare_endpoint(root='samples')

        answer = self.post(endpoint,
                           files=files,
                           data=payload)

        self.sid = answer["sample"][0]["id"]
        return self.sid

    def assign_to_family(self, sid, fname):
        """
            Assign a sample to a specific family
            @arg sid: the sample id
            @arg fid: the desired family name
        """
        self.logger.info("Assigning sample %d to family %s", sid, fname)
        endpoint = self.prepare_endpoint(root='samples')
        endpoint += str(sid) + '/'
        endpoint += 'families/'

        fam = {'family_name': fname}
        answer = self.post(endpoint, json=fam)
        return answer

    def set_abstract(self, sid, abstract):
        """
            Updates a sample's abstract
        """
        endpoint = self.prepare_endpoint(root='samples')
        endpoint += str(sid) + '/abstract/'

        json_data = dict(abstract=abstract)
        return self.post(endpoint, json=json_data)["result"]

    def get_abstract(self, sid):
        """
            Return sample's markdown abstract
        """
        endpoint = self.prepare_endpoint(root='samples')
        endpoint += str(sid) + '/abstract/'

        return self.get(endpoint)["abstract"]

    def get_sid_from_MD5(self, md5):
        """
            Returns the sample's ID
        """
        endpoint = self.prepare_endpoint(root='samples')
        endpoint += md5 + '/'

        return self.get(endpoint)


class FamilyModule(MainModule):
    """
        Utilities to manage families
    """
    def create_family(self, name, parent=None, tlp_level=3):
        """
            Create a family, and return it's id
        """
        self.logger.info("Creating family %s", name)
        endp = self.prepare_endpoint(root='family')
        json_data = dict(name=name, tlp_level=tlp_level)
        if parent is not None:
            json_data["parent"] = parent
        data = self.post(endp, json=json_data)
        return data["family"]

    def get_family(self, name):
        """
            Get the informations for a given family
        """
        self.logger.info("Getting family %s", name)
        endpoint = self.prepare_endpoint(root='family')
        endpoint += name
        answer = self.get(endpoint)
        return answer

    def set_family_abstract(self, fid, abstract):
        """
            Set a new abstract for a family
        """
        self.logger.info("Setting family abstract")
        endpoint = self.prepare_endpoint(root='family')
        endpoint += str(fid) + '/abstract/'

        json_data = dict(abstract=abstract)
        return self.post(endpoint, json=json_data)["result"]

    def add_yara(self, fid, rule_name):
        """
            Add a yara rule to a family
        """
        endpoint = self.prepare_endpoint(root='family') + str(fid)
        endpoint += '/yaras/'
        json_data = dict(rule_name=rule_name)
        return self.post(endpoint, json=json_data)["result"]


class YaraModule(MainModule):
    """
        Manage yara rules
    """
    def create_yara(self, name, rule, tlp_level=2):
        """
            Create a new yara rule
            @arg name: The rule name
            @arg rule: The rule complete text
            @arg tlp_level: The TLP
        """
        endpoint = self.prepare_endpoint(root='yaras')
        json_data = dict(name=name, rule=rule, tlp_level=tlp_level)
        answer = self.post(endpoint, json=json_data)
        return answer["id"]
