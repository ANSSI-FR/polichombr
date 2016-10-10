"""
    This file is part of Polichombr
        (c) 2016 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    This file contains the module to use the external polichombr REST API.
"""

import logging
import requests


class MainModule(object):
    """
        This module provides the main utils
        that are used by the children classes
    """
    server = None
    server_port = None
    base_uri = None

    auth_token = None
    logger = None

    def __init__(self, server="127.0.0.1", server_port=5000,
                 base_uri='/api/1.0/'):
        self.server, self.server_port = server, server_port
        self.base_uri = base_uri
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)

        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(log_format)
        self.logger.addHandler(handler)

        self.login()

    def login(self):
        """
            Initialize the auth token by issuing a call to the API
        """
        pass

    def post(self, endpoint, **kwargs):
        """
            Wrapper for requests.post
        """
        json_data, data, files = None, None, None
        if 'json' in kwargs.keys():
            json_data = kwargs['json']
        if 'data' in kwargs.keys():
            data = kwargs['data']
        if 'files' in kwargs.keys():
            files = kwargs['files']
        answer = requests.post(endpoint,
                               json=json_data,
                               data=data,
                               files=files)
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
        answer = requests.get(endpoint, params=args)
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
        endp = "http://" + self.server + ':' + str(self.server_port)
        endp += self.base_uri
        if 'root' in kwargs.keys():
            endp += kwargs['root'] + '/'
        return endp


class SampleModule(MainModule):
    """
        Uses the sample endpoint
    """

    def __init__(self):
        super(SampleModule, self).__init__()

    def send_sample(self, filename, tlp):
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

        return answer["sample"]["id"]

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


class FamilyModule(MainModule):
    """
        Utilities to manage families
    """

    def __init__(self):
        super(FamilyModule, self).__init__()

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
