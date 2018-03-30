#!/usr/bin/env python
"""

        This file is part of Polichombr.
            (c) ANSSI-FR 2018


        Description:
            This module implements all the tests for the API endpoints
"""
import os
import unittest
import tempfile
import json
import datetime
from time import sleep
from io import BytesIO
from zipfile import ZipFile
import io

import polichombr
from polichombr.controllers.api import APIControl


class ApiTestCase(unittest.TestCase):
    """
        Tests cases for the API endpoints
    """
    def setUp(self):
        self.db_fd, self.fname = tempfile.mkstemp()
        polichombr.app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+self.fname
        polichombr.app.config['TESTING'] = False
        polichombr.app.config["LOGIN_DISABLED"] = True
        polichombr.app.config['WTF_CSRF_ENABLED'] = False
        self.app = polichombr.app.test_client()
        self.auth_token = None

        with polichombr.app.app_context():
            polichombr.db.create_all()
            api = APIControl()
            api.usercontrol.create("john", "password")
            polichombr.db.session.commit()
            key = api.usercontrol.get_by_id(1).api_key

        self.auth_token = None
        self._login(key)

        self._create_sample()

    def tearDown(self):
        polichombr.db.session.remove()
        with polichombr.app.app_context():
            polichombr.db.drop_all()
        os.close(self.db_fd)
        os.unlink(self.fname)

    def _login(self, api_key):
        """
            Get an auth token
        """
        token = self.app.post("/api/1.0/auth_token/",
                              data=json.dumps({'api_key': api_key}),
                              content_type="application/json")
        self.assertEqual(token.status_code, 200)
        token = json.loads(token.get_data(as_text=True))["token"]
        self.auth_token = token

    def get(self, *args, **kwargs):
        headers = {"X-Api-Key": self.auth_token}
        kwargs["headers"] = headers
        return self.app.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        headers = {"X-Api-Key": self.auth_token}
        kwargs["headers"] = headers
        return self.app.post(*args, **kwargs)

    def patch(self, *args, **kwargs):
        headers = {"X-Api-Key": self.auth_token}
        kwargs["headers"] = headers
        return self.app.patch(*args, **kwargs)

    def delete(self, *args, **kwargs):
        headers = {"X-Api-Key": self.auth_token}
        kwargs["headers"] = headers
        return self.app.delete(*args, **kwargs)

    def _create_sample(self):
        with open("tests/example_pe.bin", "rb") as hfile:
            data = BytesIO(hfile.read())
        retval = self.post("/api/1.0/samples/",
                           data=dict({'file': (data, "toto"),
                                      'filename': "toto"},
                                     tlp_level=1, family=0),
                           follow_redirects=True)
        self.assertEqual(retval.status_code, 200)
        sleep(1)
        return retval

    def _create_family(self, name, tlp_level=None, parent=None):
        data = dict(name=name, tlp_level=tlp_level)
        if parent is not None:
            data["parent"] = parent
        retval = self.post('/api/1.0/family/',
                           data=json.dumps(data),
                           content_type="application/json")
        return retval


class ApiSampleTests(ApiTestCase):
    """
        Tests cases relatives to sample analysis and metadata
    """

    def test_get_sample_info(self):
        """
            Just check if we can access the sample id
        """
        retval = self.get('/api/1.0/samples/1/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data), 1)
        data = data['samples']
        self.assertEqual(data['id'], 1)

    def test_upload_zip_sample(self):
        """
            Trigger Issue #97
        """
        zipout = io.BytesIO()
        with ZipFile(zipout, "w") as myzip:
            myzip.write("tests/example_pe.bin")
            myzip.close()
        data = BytesIO(zipout.getvalue())
        retval = self.post("/api/1.0/samples/",
                           data=dict({'file': (data, "toto"),
                                      'filename': "toto.zip"},
                                     tlp_level=1, family=0),
                           follow_redirects=True)
        self.assertEqual(retval.status_code, 200)

    def test_get_sample_id(self):
        """
            Test access to the sample by using MD5, SHA1 and SHA256
        """
        # test getting ID by MD5
        retval = self.get('/api/1.0/samples/0f6f0c6b818f072a7a6f02441d00ac69/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data['sample_id'], 1)

        # get ID by SHA1
        retval = self.get('/api/1.0/samples/39b8a7a0a99f6e2220cf60fd860923f9df3e8d01/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data['sample_id'], 1)

        # get ID by SHA256
        retval = self.get('/api/1.0/samples/e5b830bf3d82aba009244bff86d33b10a48b03f48ca52cd1d835f033e2b445e6/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data['sample_id'], 1)

    def test_wrong_sample_hash(self):
        """
            This triggered a bug when using incorrect value for hash
        """
        url = "api/1.0/samples/abcdef/"
        retval = self.get(url)
        self.assertEqual(retval.status_code, 400)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data['error'], 400)

    def test_get_multiples_sample_info(self):
        """
            Extract some expected informations from the API
        """
        retval = self.get('/api/1.0/samples/')
        self.assertEqual(retval.status_code, 200)

        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data['samples']), 1)

        self.assertEqual(data['samples'][0]['md5'],
                         '0f6f0c6b818f072a7a6f02441d00ac69')

        self.assertEqual(data['samples'][0]['sha1'],
                         '39b8a7a0a99f6e2220cf60fd860923f9df3e8d01')

        self.assertEqual(data['samples'][0]['sha256'],
                         'e5b830bf3d82aba009244bff86d33b10a48b03f48ca52cd1d835f033e2b445e6')

        self.assertEqual(data['samples'][0]['size'], 12361)

    def test_get_analysis_data(self):
        """
            TODO
        """
        retval = self.get('/api/1.0/samples/1/analysis/')
        self.assertEqual(retval.status_code, 200)

        data = json.loads(retval.get_data(as_text=True))

        self.assertIn('analysis', list(data.keys()))

    def test_get_analyzeit_data(self):
        """
            TODO
        """
        retval = self.get('/api/1.0/samples/1/analysis/analyzeit/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data), 1)

    def test_get_peinfo_data(self):
        """
            TODO
        """
        retval = self.get('/api/1.0/samples/1/analysis/peinfo/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data), 1)

    def test_get_strings_data(self):
        """
            TODO
        """
        retval = self.get('/api/1.0/samples/1/analysis/strings/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data), 1)

    def test_sample_abstract(self):
        """
            Sets and gets the sample abstract
        """
        data = json.dumps(dict(abstract="This is a test for abstract"))
        retval = self.post('/api/1.0/samples/1/abstract/', data=data,
                           content_type="application/json")
        self.assertEqual(retval.status_code, 200)
        result = json.loads(retval.get_data(as_text=True))
        self.assertTrue(result['result'])

        retval = self.get('/api/1.0/samples/1/abstract/')
        self.assertEqual(retval.status_code, 200)
        result = json.loads(retval.get_data(as_text=True))
        self.assertIn(result['abstract'], u'This is a test for abstract')

    def test_machoc_funcinfos(self):
        retval = self.get('/api/1.0/machoc/123456')
        self.assertEqual(retval.status_code, 200)
        res = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(res), 0)

    def test_sample_functions(self):
        with polichombr.app.app_context():
            sample = polichombr.models.sample.Sample.query.get(1)
            polichombr.api.samplecontrol.add_function(sample, 0xDEAD, 0x7357BEEF, "test_function")
        retval = self.get('/api/1.0/samples/1/functions/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data), 1)
        func = data[0]
        self.assertEqual(func["address"], 0xDEAD)
        self.assertEqual(func["machoc_hash"], 0x7357BEEF)

    def test_proposed_names(self):
        """
            Test that we return correct names
        """
        with polichombr.app.app_context():
            sample = polichombr.models.sample.Sample.query.get(1)
            polichombr.api.samplecontrol.add_function(sample, 0xDEAD, 0x7357BEEF, "test_function")
            polichombr.api.samplecontrol.add_function(sample, 0xBEEF, 0x7357BEEF, "proposed_name")
            polichombr.api.samplecontrol.add_function(sample, 0xF00D, 0x7357BEEF, "sub_not_shown")
        retval = self.get('/api/1.0/samples/1/functions/proposednames/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        func = data["functions"]
        self.assertIsInstance(func, list)
        self.assertEqual(len(func), 3)
        self.assertIn("test_function", func[0]["proposed_names"])
        self.assertIn("proposed_name", func[0]["proposed_names"])
        self.assertNotIn("sub_not_shown", func[0]["proposed_names"])


class ApiFamilyTests(ApiTestCase):
    """
        Tests the families creation, hierarchy and manipulation
    """
    def test_family_creation(self):
        """
            This will test the families creation and access
        """
        retval = self._create_family("TESTFAMILY1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data['family'], 1)

        retval = self.get('/api/1.0/families/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data['families']), 1)
        family = data['families'][0]
        self.assertIn(family['name'], 'TESTFAMILY1')

        retval = self.get('/api/1.0/family/TESTFAMILY1/')
        self.assertEqual(retval.status_code, 200)
        family = json.loads(retval.get_data(as_text=True))['family']
        self.assertIn(family['name'], "TESTFAMILY1")
        self.assertEqual(family['id'], 1)

    def test_family_tlp(self):
        """
            Test the TLP level affectation for a family
        """

        retval = self._create_family("TESTFAMILY2", tlp_level=5)
        self.assertEqual(retval.status_code, 200)

        retval = self.get('/api/1.0/family/1/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        family = data['family']
        self.assertEqual(family["TLP_sensibility"], 5)

    def test_family_abstract(self):
        """
            Try to update the family abstract
        """
        self._create_family("TESTFAMILY1")
        data = json.dumps(dict(abstract="Test abstract"))
        retval = self.post("/api/1.0/family/1/abstract/", data=data,
                           content_type="application/json")
        self.assertEqual(retval.status_code, 200)
        self.assertTrue(json.loads(retval.get_data(as_text=True))["result"])

        retval = self.get("/api/1.0/family/1/")
        data = json.loads(retval.get_data(as_text=True))["family"]
        self.assertIn(data["abstract"], "Test abstract")

    def test_subfamilies(self):
        """
            Can we manage a hierarchical family organization?
        """
        self._create_family("MOTHER FAMILY")
        self._create_family("CHILD FAMILY", parent="MOTHER FAMILY")

        retval = self.get('/api/1.0/family/1/')
        data = json.loads(retval.get_data(as_text=True))["family"]

        self.assertEqual(len(data['subfamilies']), 1)
        self.assertIn(data['subfamilies'][0]["name"], "CHILD FAMILY")

        retval = self.get('/api/1.0/family/2/')
        data = json.loads(retval.get_data(as_text=True))["family"]
        self.assertEqual(data["parent_id"], 1)

    def test_assign_sample_to_family(self):
        """
            Can we affect a sample to a family with the API?
        """
        self._create_family("TESTFAMILY")

        retval = self.post("/api/1.0/samples/1/families/",
                           data=json.dumps(dict(family_name="TESTFAMILY")),
                           content_type="application/json")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        retval = self.get("/api/1.0/family/1/")
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["family"]["samples"]), 1)
        self.assertEqual(data["family"]["samples"][0]["id"], 1)

    def test_export_family_sample_archive(self):
        self._create_family("TESTFAMILY")

        retval = self.post("/api/1.0/samples/1/families/",
                           data=json.dumps(dict(family_name="TESTFAMILY")),
                           content_type="application/json")

        for tlp in range(1, 6):
            retval = self.get("/api/1.0/family/1/export/" + str(tlp) + "/samplesarchive/")
            self.assertEqual(retval.status_code, 200)
            self.assertIn("application/x-tar", retval.headers["Content-Type"])
            self.assertIn("attachment; filename=export.tar.gz",
                          retval.headers["Content-Disposition"])

            if tlp >= 3:
                self.assertGreater(int(retval.headers["Content-Length"]), 200)
            else:
                # tlp is < to the sample tlp, it should not be exported
                self.assertLess(int(retval.headers["Content-Length"]), 200)

    def test_export_openioc(self):
        """
            Can we export an openIOC for a given family
        """
        self._create_family("TESTFAMILY")
        retval = self.get("/api/1.0/family/1/export/4/detection/openioc/")
        self.assertEqual(retval.status_code, 200)
        self.assertIn("ioc", retval.get_data(as_text=True))

        retval = self.get("/api/1.0/family/1/export/4/samplesioc/")
        self.assertEqual(retval.status_code, 200)
        self.assertIn("ioc", retval.get_data(as_text=True))


class ApiYaraTests(ApiTestCase):
    """
        Yara rules creation and management
    """
    def _create_yara(self, name, rule, tlp_level=None):
        retval = self.post('/api/1.0/yaras/',
                           data=json.dumps(dict(name=name,
                                                rule=rule,
                                                tlp_level=tlp_level)),
                           content_type="application/json")
        return retval

    def _update_yara(self, name, rule, tlp_level=None):
        retval = self.patch('/api/1.0/yaras/',
                            data=json.dumps(dict(name=name,
                                                 rule=rule,
                                                 tlp_level=tlp_level)),
                            content_type="application/json")
        return retval

    def test_yara_creation(self):
        """
            Creates an example yara rule,
            and try to get it back
        """
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""
        retval = self._create_yara("TESTYARA", rule_text)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(data["id"], 1)

        retval = self.get("/api/1.0/yaras/")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data['yara_rules']), 1)
        rule = data['yara_rules'][0]
        self.assertIn(rule['name'], "TESTYARA")
        self.assertEqual(rule['TLP_sensibility'], 3)
        self.assertIn(rule['raw_rule'], rule_text)

    def test_yara_tlp(self):
        """
            Is the TLP correctly managed for a yara rule?
        """
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""
        retval = self._create_yara("TESTYARA", rule_text, tlp_level=4)
        retval = self.get("/api/1.0/yaras/")
        data = json.loads(retval.get_data(as_text=True))
        rule = data['yara_rules'][0]
        self.assertEqual(rule['TLP_sensibility'], 4)

    def test_yara_family(self):
        """
            Test for correct affectation of a yara to a family
        """
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""
        retval = self._create_yara("TESTYARA", rule_text)
        self._create_family("TESTFAMILY")
        retval = self.post('/api/1.0/family/1/yaras/',
                               data=json.dumps(dict(rule_name="TESTYARA")),
                               content_type="application/json")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        # test wrong yara name
        retval = self.post('/api/1.0/family/1/yaras/',
                               data=json.dumps(dict(rule_name="WRONGYARA")),
                               content_type="application/json")
        self.assertEqual(retval.status_code, 400)

        retval = self.get('/api/1.0/family/1/export/3/detection/yara')
        self.assertEqual(retval.status_code, 200)
        self.assertIn("TESTYARA", retval.get_data(as_text=True))
        self.assertIn("4D 5A", retval.get_data(as_text=True))

        # test with an inferior tlp level
        retval = self.get('/api/1.0/family/1/export/1/detection/yara')
        self.assertEqual(retval.status_code, 200)
        self.assertNotIn("TESTYARA", retval.get_data(as_text=True))
        self.assertNotIn("4D 5A", retval.get_data(as_text=True))


    def test_remove_from_family(self):
        """
            XXX, this is actually in the web UI, should be migrated in the API
        """
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""
        retval = self._create_yara("TESTYARA", rule_text)
        self._create_family("TESTFAMILY")
        retval = self.post('/api/1.0/family/1/yaras/',
                               data=json.dumps(dict(rule_name="TESTYARA")),
                               content_type="application/json")
        retval = self.get("/family/1/deleteyara/1")
        # are we redirected to the family view?
        self.assertEqual(retval.status_code, 302)
        self.assertIn("href=\"/family/1", retval.get_data(as_text=True))

        # is the user flashed with success?
        retval = self.get("/index/")
        self.assertIn("Removed yara TESTYARA from family TESTFAMILY", retval.get_data(as_text=True))


#     def test_yara_update(self):
        # rule_text = """rule toto{
            # strings:
                # $1 = {4D 5A}
            # condition:
                # $1 at 0
        # }"""
        # retval = self._create_yara("TESTYARA", rule_text, tlp_level=4)

        # # Try to update the yara
        # retval = self._update_yara("TESTYARA", rule_text.replace('$1', '$MZ'))
        # self.assertEqual(retval.status_code, 200)
        # data = json.loads(retval.get_data(as_text=True))
        # self.assertTrue(data["result"])

        # # Next check for the changes in the resulting data
        # retval= self.get("/api/1.0/yaras/")
        # data = json.loads(retval.get_data(as_text=True))
        # rule = data['yara_rules'][0]
        # self.assertIn(rule["raw_rule"], rule_text.replace('$1', '$MZ'))


class ApiIDAActionsTests(ApiTestCase):
    """
        Tests storage and synchronization for implemented IDA Pro types.
    """
    def _push_comment(self, sid=1, address=None, comment=None):
        retval = self.post('/api/1.0/samples/'+str(sid)+'/comments/',
                               data=json.dumps(dict(address=address, comment=comment)),
                               content_type="application/json")
        return retval

    def _create_struct(self, sid=1, name=None):
        retval = self.post('/api/1.0/samples/'+str(sid)+'/structs/',
                               data=json.dumps(dict(name=name)),
                               content_type="application/json")
        return retval

    def _rename_struct(self, sid=1, struct_id=1, name=None):
        retval = self.patch("/api/1.0/samples/" + str(sid) + "/structs/" + str(struct_id) + "/",
                                data=json.dumps(dict(name=name)),
                                content_type="application/json")
        return retval

    def _create_struct_member(self, sid=1, struct_id=None, mname=None, size=0, offset=0):
        url = '/api/1.0/samples/' + str(sid)
        url += '/structs/' + str(struct_id)
        url += '/members/'
        retval = self.post(url,
                               data=json.dumps(dict(name=mname,
                                                    size=size,
                                                    offset=offset)),
                               content_type="application/json")
        return retval

    def _update_struct_member_name(self, sid=1, struct_id=None, mid=None, newname=""):
        url = '/api/1.0/samples/' + str(sid)
        url += '/structs/' + str(struct_id)
        url += '/members/'
        retval = self.patch(url,
                                data=json.dumps(dict(mid=mid, newname=newname)),
                                content_type="application/json")
        return retval

    def _update_struct_member_size(self, sid=1, struct_id=None, mid=None, newsize=0):
        url = '/api/1.0/samples/' + str(sid)
        url += '/structs/' + str(struct_id)
        url += '/members/'
        retval = self.patch(url,
                                data=json.dumps(dict(mid=mid, newsize=newsize)),
                                content_type="application/json")
        return retval

    def _get_all_structs(self, sid=1):
        retval = self.get('/api/1.0/samples/' + str(sid) +
                              '/structs/')
        return retval

    def _get_one_struct(self, sid=1, struct_id=1):
        url = '/api/1.0/samples/' + str(sid)
        url += '/structs/'
        url += str(struct_id) + '/'
        retval = self.get(url)
        return retval

    def _get_comment(self, sid=1, address=None):
        retval = self.get('/api/1.0/samples/' + str(sid) +
                              '/comments/',
                              data=json.dumps({'address':address}),
                              content_type="application/json")
        return retval

    def _push_name(self, sid=1, address=None, name=None):
        retval = self.post('/api/1.0/samples/'+str(sid)+'/names/',
                               data=json.dumps(dict(address=address, name=name)),
                               content_type="application/json")
        return retval

    def _get_name(self, sid=1, address=None):
        url = '/api/1.0/samples/' + str(sid) + '/names/'
        if address is not None:
            url += '?addr='
            url += hex(address)
        retval = self.get(url)
        return retval

    def _create_type(self, sid=1, address=None, typedef=None):
        retval = self.post('/api/1.0/samples/'+str(sid)+'/types/',
                               data=json.dumps(dict(address=address,
                                                    typedef=typedef)),
                               content_type="application/json")
        return retval

    def _get_type(self, sid=1, address=None):
        url = '/api/1.0/samples/' + str(sid)
        url += '/types/'
        if address is not None:
            url += "?addr="
            url += hex(address)

        return self.get(url)

    @staticmethod
    def _format_timedelta():
        """
        wrapper for strftime and 1 day offset
        """
        offset = datetime.datetime.now() + datetime.timedelta(days=1)
        offset = datetime.datetime.strftime(offset, '%Y-%m-%dT%H:%M:%S.%f')
        return offset

    def test_get_all(self):
        """
            Get all informations about a sample
        """
        self._push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self._push_name(address=0xDEADBEEF, name="TESTNAME")
        self._push_name(address=0xC0FFEE, name="NAME @ C0FFEE")
        self._push_comment(address=0xBADF00D, comment="TESTCOMMENT2")
        self._create_struct(name="ThisIsAStruct")
        retval = self.get("/api/1.0/samples/1/idaactions/")
        self.assertEqual(retval.status_code, 200)
        actions = json.loads(retval.get_data(as_text=True))

        # {"timestamp": , "idaactions":}
        self.assertEqual(len(actions), 2)
        self.assertIn("timestamp", list(actions.keys()))
        self.assertIn("idaactions", list(actions.keys()))
        self.assertEqual(len(actions["idaactions"]), 5)
        for action in actions["idaactions"]:
            self.assertIn("timestamp", list(action.keys()))
            self.assertIn("type", list(action.keys()))
            self.assertIn("data", list(action.keys()))
            self.assertIn("address", list(action.keys()))

        self.assertIn(actions["idaactions"][0]["type"], "idacomments")
        self.assertEqual(actions["idaactions"][0]["address"], 0xDEADBEEF)
        self.assertIn(actions["idaactions"][0]["data"], "TESTCOMMENT1")

        self.assertIn(actions["idaactions"][1]["type"], "idanames")
        self.assertEqual(actions["idaactions"][1]["address"], 0xDEADBEEF)
        self.assertIn(actions["idaactions"][1]["data"], "TESTNAME")

        self.assertIn(actions["idaactions"][2]["type"], "idanames")
        self.assertEqual(actions["idaactions"][2]["address"], 0xC0FFEE)
        self.assertIn(actions["idaactions"][2]["data"], "NAME @ C0FFEE")

        self.assertIn(actions["idaactions"][3]["type"], "idacomments")
        self.assertEqual(actions["idaactions"][3]["address"], 0xBADF00D)
        self.assertIn(actions["idaactions"][3]["data"], "TESTCOMMENT2")

        self.assertIn(actions["idaactions"][4]["type"], "idastructs")
        self.assertEqual(actions["idaactions"][4]["address"], 0)
        self.assertIn(actions["idaactions"][4]["data"], "ThisIsAStruct")

    def test_push_comments(self):
        """
            Can we push comments for a sample?
        """
        retval = self._push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

    def test_get_comment(self):
        """
            This endpoint is used to get comments for a specific address
        """
        retval = self._push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

        retval = self._get_comment(address=0xDEADBEEF)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertIn(data['comments'][0]["data"], u"TESTCOMMENT1")
        self.assertEqual(data['comments'][0]["address"], 0xDEADBEEF)

    def test_get_multiple_comments(self):
        retval = self._push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

        retval = self._push_comment(address=0xBADF00D, comment="TESTCOMMENT2")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

        retval = self._get_comment()
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data['comments']), 2)
        self.assertIn(data['comments'][0]["data"], u"TESTCOMMENT1")
        self.assertEqual(data['comments'][0]["address"], 0xDEADBEEF)
        self.assertIn(data['comments'][1]["data"], u"TESTCOMMENT2")
        self.assertEqual(data['comments'][1]["address"], 0xBADF00D)

    def test_action_timestamp(self):
        """
            Test getting different results with different timestamps
        """
        self._push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        offset = self._format_timedelta()
        retval = self.get('/api/1.0/samples/1/comments/?timestamp='+offset)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["comments"]), 0)

        # now test with invalid timestamp
        offset += "12345Z"
        retval = self.get('/api/1.0/samples/1/comments/?timestamp='+offset)
        self.assertEqual(retval.status_code, 500)

        retval = self.get('/api/1.0/samples/1/comments/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["comments"]), 1)

        self._push_name(address=0xDEADBEEF, name="TESTNAME")
        offset = self._format_timedelta()
        retval = self.get('/api/1.0/samples/1/names/?timestamp='+offset)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["names"]), 0)

        retval = self.get('/api/1.0/samples/1/names/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["names"]), 1)

        self._create_struct(name="TESTSTRUCTURE")
        offset = self._format_timedelta()
        retval = self.get('/api/1.0/samples/1/structs/?timestamp='+offset)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["structs"]), 0)

        retval = self.get('/api/1.0/samples/1/structs/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["structs"]), 1)

    def test_push_name(self):
        """
            Simulate a renaming done from IDA
        """
        retval = self._push_name(address=0xDEADBEEF, name="TESTNAME1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

    def test_get_names(self):
        """
            This endpoint is used to get names for a specific address
        """
        retval = self._push_name(address=0xDEADBEEF, name="TESTNAME1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

        retval = self._get_name(address=0xDEADBEEF)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertIn(data['names'][0]["data"], u"TESTNAME1")
        self.assertEqual(data['names'][0]["address"], 0xDEADBEEF)

    def test_create_struct(self):
        """
            Simple structure creation and access
        """
        retval = self._create_struct(sid=1, name="StructName1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        # check if the structure is in the complete listing
        retval = self._get_all_structs(sid=1)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertIn("StructName1", data["structs"][0]["name"])
        self.assertEqual(0, data["structs"][0]["size"])

        # check if we can access the structure alone
        retval = self._get_one_struct(sid=1, struct_id=1)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        struct = data["structs"]
        self.assertIn("StructName1", struct["name"])
        self.assertEqual(0, struct["size"])

    def test_rename_struct(self):
        self._create_struct(sid=1, name="StructName1")
        retval = self._rename_struct(sid=1, struct_id=1, name="NewStructName")
        self.assertEqual(retval.status_code, 200)

        retval = self._get_all_structs()
        data = json.loads(retval.get_data(as_text=True))
        self.assertNotIn("StructName1", data["structs"][0]["name"])
        self.assertIn("NewStructName", data["structs"][0]["name"])

    def test_get_struct_by_name(self):
        self._create_struct(sid=1, name="StructName1")

        retval = self._get_all_structs(sid=1)
        retval = self.get("/api/1.0/samples/1/structs/StructName1/")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertIn(data["structs"]["name"], u"StructName1")
        retval = self.get("/api/1.0/samples/1/structs/XXX/")
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(list(data["structs"].keys())), 0)

    def test_delete_struct(self):
        self._create_struct(sid=1, name="StructName1")
        self._create_struct(sid=1, name="StructName2")

        retval = self.delete("/api/1.0/samples/1/structs/1/")
        self.assertEqual(retval.status_code, 200)

        retval = self._get_all_structs()
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(len(data["structs"]), 1)
        self.assertNotIn("StructName1", data["structs"][0]["name"])

    def test_create_multiple_structs(self):
        """
            This will test if we can access multiple structs for one sample
        """
        # create structs
        retval = self._create_struct(sid=1, name="StructName1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        retval = self._create_struct(sid=1, name="StructName2")
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        # get the structs
        retval = self._get_all_structs(sid=1)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertEqual(2, len(data["structs"]))
        struct1 = data["structs"][0]
        struct2 = data["structs"][1]
        self.assertIn("StructName1", struct1["name"])
        self.assertIn("StructName2", struct2["name"])
        self.assertEqual(0, struct1["size"])
        self.assertEqual(0, struct2["size"])

    def test_create_struct_member(self):
        """
            Member creation
        """
        # first create a structre
        self._create_struct(sid=1, name="StructName1")
        # then add a member to it
        retval = self._create_struct_member(struct_id=1,
                                            mname="MemberName1",
                                            size=4,
                                            offset=0)
        # Is the member OK?
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        # can we get the member in the structure
        retval = self._get_one_struct(sid=1, struct_id=1)
        data = json.loads(retval.get_data(as_text=True))
        struct = data["structs"]

        self.assertEqual(len(struct["members"]), 1)
        self.assertEqual(struct["size"], 4)
        member = struct["members"][0]
        self.assertIn("MemberName1", member["name"])
        self.assertEqual(4, member["size"])
        self.assertEqual(0, member["offset"])

    def test_create_members_multistruct(self):
        """
            Triggers a bug showing that members are
            affected to all structures off a sample?
        """
        self._create_struct(sid=1, name="StructName1")
        self._create_struct(sid=1, name="StructName2")

        self._create_struct_member(struct_id=1,
                                   mname="Struct1.MemberName1",
                                   size=4,
                                   offset=0)
        self._create_struct_member(struct_id=1,
                                   mname="Struct1.MemberName2",
                                   size=4,
                                   offset=8)
        self._create_struct_member(struct_id=2,
                                   mname="Struct2.MemberName1",
                                   size=4,
                                   offset=0)

        retval = self._get_all_structs()
        data = json.loads(retval.get_data(as_text=True))

        self.assertEqual(len(data["structs"][0]["members"]), 2)
        self.assertEqual(len(data["structs"][1]["members"]), 1)

    def test_create_struct_members(self):
        """
            Test for multiples members
        """
        self._create_struct(sid=1, name="StructName1")
        self._create_struct_member(struct_id=1,
                                   mname="MemberName1",
                                   size=4,
                                   offset=0)

        self._create_struct_member(struct_id=1,
                                   mname="MemberName2",
                                   size=2,
                                   offset=4)

        self._create_struct_member(struct_id=1,
                                   mname="MemberName3",
                                   size=2,
                                   offset=6)

        self._create_struct_member(struct_id=1,
                                   mname="MemberName4",
                                   size=4,
                                   offset=8)

        retval = self._get_one_struct(sid=1, struct_id=1)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))

        struct = data["structs"]

        # do we have all the members
        self.assertEqual(len(struct["members"]), 4)
        self.assertEqual(struct["size"], 12)

        member = struct["members"][0]
        self.assertIn("MemberName1", member["name"])
        self.assertEqual(4, member["size"])
        self.assertEqual(0, member["offset"])

        member = struct["members"][1]
        self.assertIn("MemberName2", member["name"])
        self.assertEqual(2, member["size"])
        self.assertEqual(4, member["offset"])

        member = struct["members"][2]
        self.assertIn("MemberName3", member["name"])
        self.assertEqual(2, member["size"])
        self.assertEqual(6, member["offset"])

        member = struct["members"][3]
        self.assertIn("MemberName4", member["name"])
        self.assertEqual(4, member["size"])
        self.assertEqual(8, member["offset"])

    def test_idatypes(self):
        """
            IDA Types
        """
        ret = self._create_type(sid=1, address=0xDEADBEEF, typedef='void *')
        self.assertEqual(ret.status_code, 200)
        res = json.loads(ret.get_data(as_text=True))
        self.assertTrue(res["result"])

        # test for getting this type in all types
        ret = self._get_type(sid=1)
        self.assertEqual(ret.status_code, 200)
        types = json.loads(ret.get_data(as_text=True))['typedefs']
        self.assertEqual(len(types), 1)
        self.assertIn(types[0]["data"], 'void *')

        # test for getting type filtered by address
        ret = self._get_type(sid=1, address=0xDEADBEEF)
        self.assertEqual(ret.status_code, 200)
        types = json.loads(ret.get_data(as_text=True))['typedefs']
        self.assertEqual(len(types), 1)
        self.assertIn(types[0]["data"], 'void *')

        # test if there is no comment at a specified address
        ret = self._get_type(sid=1, address=0x1234)
        self.assertEqual(ret.status_code, 200)
        types = json.loads(ret.get_data(as_text=True))['typedefs']
        self.assertEqual(len(types), 0)

        # test adding a new type at different address and getting it too
        self._create_type(sid=1, address=0xBADF00D, typedef='int testtype(int dwTest, char cType)')
        ret = self._get_type(sid=1)
        self.assertEqual(ret.status_code, 200)
        types = json.loads(ret.get_data(as_text=True))['typedefs']
        self.assertEqual(len(types), 2)
        self.assertIn(types[0]["data"], 'void *')
        self.assertIn(types[1]["data"], 'int testtype(int dwTest, char cType)')

    def test_struct_member_update(self):
        """
            Update size, name or offset
        """
        self._create_struct(sid=1, name="StructName1")
        self._create_struct_member(struct_id=1,
                                   mname="MemberName1",
                                   size=4,
                                   offset=0)

        self._create_struct_member(struct_id=1,
                                   mname="MemberName2",
                                   size=2,
                                   offset=4)

        retval = self._update_struct_member_name(struct_id=1,
                                                 mid=1,
                                                 newname="NewMemberName1")

        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data['result'])

        retval = self._get_one_struct(sid=1, struct_id=1)
        data = json.loads(retval.get_data(as_text=True))
        mstruct = data['structs']
        member = mstruct['members'][0]
        self.assertIn('NewMemberName1', member['name'])

        # test when downgrading the size of first member
        retval = self._update_struct_member_size(struct_id=1,
                                                 mid=1,
                                                 newsize=2)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        retval = self._get_one_struct(sid=1, struct_id=1)
        data = json.loads(retval.get_data(as_text=True))
        mstruct = data['structs']
        member = mstruct['members'][0]
        self.assertEqual(member['size'], 2)
        self.assertEqual(mstruct['size'], 6)

        # test when downgrading the last member size
        retval = self._update_struct_member_size(struct_id=1,
                                                 mid=2,
                                                 newsize=1)
        retval = self._get_one_struct(sid=1, struct_id=1)
        data = json.loads(retval.get_data(as_text=True))
        mstruct = data['structs']
        member = mstruct['members'][1]
        self.assertEqual(member['size'], 1)
        self.assertEqual(mstruct['size'], 5)

        # test when upgrading the last member size
        retval = self._update_struct_member_size(struct_id=1,
                                                 mid=2,
                                                 newsize=4)

        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.get_data(as_text=True))
        self.assertTrue(data["result"])

        retval = self._get_one_struct(sid=1, struct_id=1)

        data = json.loads(retval.get_data(as_text=True))
        mstruct = data['structs']
        member = mstruct['members'][1]
        self.assertEqual(member['size'], 4)
        self.assertEqual(mstruct['size'], 8)
        # if upgrading the size and overlapping the next member,
        # adopt the same behavior as IDA and remove the second member
        # TODO!!!
        # self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
