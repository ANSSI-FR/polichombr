"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        This file implements the main connection class
        which interacts with the remote API
"""

import gzip
import httplib
import json
import datetime
import logging
import ssl

from StringIO import StringIO
from string import lower

import idc

logger = logging.getLogger(__name__)


class SkelConnection(object):
    """
        HTTP(S) API management
    """
    sample_id = None
    remote_path = None
    http_debug = None
    api_key = None
    poli_server = None
    poli_port = None
    h_conn = None
    is_online = False

    def __init__(self, skel_config=None):
        """
            Here skel_config should be a SkelConfig object
        """
        if skel_config is None:
            raise ValueError
        self.http_debug = skel_config.debug_http
        self.remote_path = skel_config.poli_remote_path
        self.api_key = skel_config.poli_apikey
        self.poli_server = skel_config.poli_server
        self.poli_port = skel_config.poli_port

        self.h_conn = None
        self.auth_token = None
        self.is_online = False
        self.sample_id = None

    def get_online(self):
        """
            Connect to the server
        """
        try:
            self.__do_init()
        except Exception:
            logger.exception("The polichombr server seems down")
            return False
        return True

    def __do_init(self):
        """
            Initiate connection handle
        """
        if self.http_debug is True:
            logger.info("Connecting using simple HTTP")
            self.h_conn = httplib.HTTPConnection(self.poli_server,
                                                 self.poli_port)
        else:
            logger.info("Connecting using HTTPS")
            ssl_context = ssl._create_unverified_context()
            self.h_conn = httplib.HTTPSConnection(self.poli_server,
                                                  self.poli_port,
                                                  context=ssl_context)

        self.h_conn.connect()
        self.login()
        self.is_online = True
        self.init_sample_id()

    def close_connection(self):
        """
            Cleanup the connection
        """
        logger.debug("Closing connection")
        if self.h_conn is not None:
            self.h_conn.close()
        self.is_online = False
        self.sample_id = None

    def login(self):
        """
            Get an authentication token from the server
        """
        data = json.dumps({'api_key': self.api_key})
        headers = {"Accept-encoding": "gzip, deflate",
                   "Content-type": "application/json",
                   "Accept": "*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5"}

        self.h_conn.request("POST",
                            "/api/1.0/auth_token/",
                            data,
                            headers)
        res = self.h_conn.getresponse()
        if res.status != 200:
            idc.warning("Error, cannot login to Polichombr!")
            raise IOError
        token = json.loads(res.read())["token"]
        self.auth_token = token

    def poli_request(self, endpoint, data, method="POST"):
        """
            @arg : endpoint The API target endpoint
            @arg : data dictionary
            @return : dict issued from JSON
        """
        if not self.is_online:
            logger.error("Cannot send requests while not connected")
            raise IOError
        headers = {"Accept-encoding": "gzip, deflate",
                   "Content-type": "application/json",
                   "Accept": "*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5",
                   "Connection": "Keep-Alive",
                   "X-Api-Key": self.auth_token}
        json_data = json.dumps(data)
        try:
            self.h_conn.request(method, endpoint, json_data, headers)
        except (httplib.CannotSendRequest, httplib.BadStatusLine) as e:
            logger.error("Error during request, retrying")
            self.close_connection()
            self.get_online()
            self.h_conn.request(method, endpoint, json_data, headers)
        res = self.h_conn.getresponse()

        if res.status == 401:
            logger.error("Token is invalid, trying to login again")
            self.login()
            return None
        elif res.status != 200:
            logger.error("The %s request didn't go as expected", method)
            logger.debug("Status code was %d and content was %s",
                         res.status, res.read())
            return None
        content_type = res.getheader("Content-Encoding")
        if content_type == "gzip":
            buf = StringIO(res.read())
            res = gzip.GzipFile(fileobj=buf)
        data = res.read()
        try:
            result = json.loads(data)
        except BaseException:
            raise IOError
        return result

    def poli_post(self, endpoint="/", data=None):
        result = self.poli_request(endpoint, data, method='POST')
        return result

    def poli_get(self, endpoint="/", data=None):
        result = self.poli_request(endpoint, data, method='GET')
        return result

    def poli_put(self, endpoint="/", data=None):
        result = self.poli_request(endpoint, data, method='PUT')
        return result

    def poli_delete(self, endpoint='/', data=None):
        result = self.poli_request(endpoint, data, method='DELETE')
        return result

    def poli_patch(self, endpoint='/', data=None):
        result = self.poli_request(endpoint, data, method='PATCH')
        return result

    def send_sample(self, filedata):
        """
            Ugly wrapper for uploading a file in multipart/form-data
        """
        endpoint = "/api/1.0/samples/"
        headers = {"Accept-encoding": "gzip, deflate",
                   "X-Api-Key": self.auth_token}

        method = "POST"
        boundary = "70f6e331562f4b8f98e5f9590e0ffb8e"
        headers["Content-type"] = "multipart/form-data; boundary=" + boundary
        body = "--" + boundary
        body += "\r\n"
        body += "Content-Disposition: form-data; name=\"filename\"\r\n"
        body += "\r\n"
        body += idc.get_root_filename()
        body += "\r\n\r\n"
        body += "--" + boundary + "\r\n"

        body += "Content-Disposition: form-data;"
        body += "name=\"file\"; filename=\"file\"\r\n"
        body += "\r\n"
        body += filedata.read()
        body += "\r\n--"
        body += boundary
        body += "--\r\n"

        self.h_conn.request(method, endpoint, body, headers)
        res = self.h_conn.getresponse()
        data = res.read()
        try:
            result = json.loads(data)
        except BaseException:
            logger.exception("Cannot load json data from server")
            result = None
        return result

    def get_sample_id(self):
        """
            Query the server for the sample ID
        """
        endpoint = "/api/1.0/samples/"
        endpoint += lower(idc.retrieve_input_file_md5())
        endpoint += "/"
        try:
            data = self.poli_get(endpoint)
            if data["sample_id"] is not None:
                return data["sample_id"]
            else:
                return False
        except BaseException:  # 404?
            return False

    def init_sample_id(self):
        """
            test if the remote sample exists,
            if not, we upload it
        """
        if self.sample_id is None:
            self.sample_id = self.get_sample_id()
            if not self.sample_id:
                logger.warning("Sample not found on server, uploading it")
                self.send_sample(open(idc.get_root_filename(), 'rb'))
                self.sample_id = self.get_sample_id()
                logger.info("Sample ID: %d", self.sample_id)


class SkelIDAConnection(SkelConnection):
    def push_comment(self, address=0, comment=None):
        """
            Push a standard comment
        """
        if comment is None:
            return False
        data = {"address": address,
                "comment": comment}
        endpoint = self.prepare_endpoint('comments')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            logger.debug(
                "Comment %s sent for address 0x%x",
                comment,
                address)
        else:
            logger.error("Cannot send comment %s ( 0x%x )", comment, address)
        return res["result"]

    def push_type(self, address, mtype=None):
        """
            Push defined types, parsed with prepare_parse_type
        """
        data = {"address": address,
                "typedef": mtype}
        endpoint = self.prepare_endpoint('types')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            logger.debug("New type %s sent for address 0x%x", mtype, address)
        else:
            logger.error("Cannot send type %s ( 0x%x )", mtype, address)
        return res["result"]

    def get_abstract(self):
        endpoint = self.prepare_endpoint("abstract")
        abstract = self.poli_get(endpoint)
        return abstract["abstract"]

    def push_abstract(self, abstract):
        endpoint = self.prepare_endpoint("abstract")
        data = {"abstract": abstract}
        res = self.poli_post(endpoint, data)
        if res["result"]:
            logger.debug("Abstract sent!")
        else:
            logger.error("Cannot send abstract...\n Error %s", res)

    def get_comments(self, timestamp=None):
        endpoint = self.prepare_endpoint('comments')
        format_ts = "%Y-%m-%dT%H:%M:%S.%f"
        if timestamp is not None:
            endpoint += "?timestamp="
            endpoint += datetime.datetime.strftime(timestamp, format_ts)
        res = self.poli_get(endpoint)
        return res["comments"]

    def get_names(self, timestamp=None):
        """
            Get all names defined in the database
        """
        endpoint = self.prepare_endpoint('names')
        format_ts = "%Y-%m-%dT%H:%M:%S.%f"
        if timestamp is not None:
            endpoint += "?timestamp="
            endpoint += datetime.datetime.strftime(timestamp, format_ts)
        res = self.poli_get(endpoint)
        return res["names"]

    def get_proposed_names(self):
        """
            Get machoc proposed names
            Returns a list of dictionaries by address
        """
        endpoint = self.prepare_endpoint("functions/proposednames")
        res = self.poli_get(endpoint)
        return res["functions"]

    def push_name(self, address=0, name=None):
        """
            Send a define name, be it func or area
        """
        if name is None:
            return False
        data = {"address": address,
                "name": name}
        endpoint = self.prepare_endpoint('names')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            logger.debug("sent name %s at 0x%x", name, address)
        else:
            logger.error("failed to send name %s", name)
        return True

    def create_struct(self, struct_name):
        """
            Create a structure in the database
            @arg:
                the structure name
            @return:
                The struct id, False if failed
        """
        endpoint = self.prepare_endpoint('structs')
        data = dict(name=struct_name)
        res = self.poli_post(endpoint, data)
        if not res["result"]:
            return False
        sid = res["structs"][0]["id"]
        return sid

    def get_struct_by_name(self, name):
        """
            Return the remote struct id given a name
        """
        endpoint = self.prepare_endpoint("structs/"+name)
        res = self.poli_get(endpoint)
        if "name" in res["structs"].keys():
            return res["structs"]["id"]
        else:
            return None

    def get_member_by_name(self, sid, name):
        """
            Should probably be implemented server side
        """
        endpoint = self.prepare_endpoint("structs/"+str(sid))
        res = self.poli_get(endpoint)
        if "members" in res["structs"].keys():
            for member in res["structs"]["members"]:
                if member["name"] == name:
                    return member["id"]
        return None

    def rename_struct(self, struct_id, new_name):
        """
            Rename a struct
        """
        endpoint = self.prepare_endpoint("structs/"+str(struct_id))
        data = dict(name=new_name)
        res = self.poli_patch(endpoint, data)
        return res

    def delete_struct(self, struct_id):
        endpoint = self.prepare_endpoint("structs/"+str(struct_id))
        res = self.poli_delete(endpoint)
        return res

    def create_struct_member(self, sid, name, start_offset):
        """
            Create a new member for a struct.
        """
        endpoint = self.prepare_endpoint("structs/"+str(sid)+"/members")
        data = dict(name=name, size=1, offset=start_offset)
        res = self.poli_post(endpoint, data=data)
        return res

    def resize_struct_member(self, sid, mid, size):
        """
            Sets a new size for a struct member
        """
        raise NotImplementedError

    def rename_struct_member(self, sid, mid, name):
        """
            Rename a struct member
        """
        endpoint = self.prepare_endpoint("structs/"+str(sid)+"/members")
        data = dict(mid=mid, newname=name)
        res = self.poli_patch(endpoint, data=data)
        return res

    def prepare_endpoint(self, submodule):
        """
            Prepare a standard API endpoint
        """
        endpoint = self.remote_path + "samples/"
        endpoint += str(self.sample_id)
        endpoint += "/" + submodule + "/"
        return endpoint
