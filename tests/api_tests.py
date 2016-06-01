#!/usr/bin/env python
import os
import unittest
import tempfile
import json
from time import sleep
from StringIO import StringIO

import app
from app.controllers.api import APIControl


class MainTestCase(unittest.TestCase):
    """
        Tests cases for the API endpoints
    """
    def setUp(self):
        self.db_fd, self.fname = tempfile.mkstemp()
        app.app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+self.fname
        app.app.config['TESTING'] = True
        app.app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.app.test_client()
        app.db.create_all()
        api = APIControl()
        api.usercontrol.create("john", "password")
        self.create_sample()
        app.db.session.commit()

    def tearDown(self):
        app.db.session.remove()
        app.db.drop_all()
        os.close(self.db_fd)
        os.unlink(self.fname)

    def login(self, username, password):
        return self.app.post("/login/",
                             data=dict(
                                 username=username,
                                 password=password),
                             follow_redirects=True)

    def create_sample(self):
        with open("tests/example_pe.bin", "rb") as hfile:
            data = StringIO(hfile.read())
        self.login("john", "password")
        retval = self.app.post("/samples/",
                               content_type='multipart/form-data',
                               data=dict({'file': (data, "toto")},
                                         level=1, family=0),
                               follow_redirects=True)
        sleep(3)
        return retval

    def push_comment(self, sid=1, address=None, comment=None):
        retval = self.app.post('/api/1.0/samples/'+str(sid)+'/comments/',
                               data=json.dumps(dict(address=address, comment=comment)),
                               content_type="application/json")
        return retval


    def get_comment(self, sid=1, address=None):
        retval = self.app.get('/api/1.0/samples/' + str(sid) +
                              '/comments/',
                              data=json.dumps({'address':address}),
                              content_type="application/json")
        return retval

    def push_name(self, sid=1, address=None, name=None):
        retval = self.app.post('/api/1.0/samples/'+str(sid)+'/names/',
                               data=json.dumps(dict(address=address, name=name)),
                               content_type="application/json")
        return retval

    def get_name(self, sid=1, address=None):
        retval = self.app.get('/api/1.0/samples/' + str(sid) +
                              '/names/',
                              data=json.dumps({'address': address}),
                              content_type="application/json")
        return retval

    def test_get_sample_info(self):
        retval = self.app.get('/api/1.0/samples/1/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertEqual(data['id'], 1)

    def test_get_multiples_sample_info(self):
        retval = self.app.get('/api/1.0/samples/')
        self.assertEqual(retval.status_code, 200)

        data = json.loads(retval.data)
        self.assertEqual(len(data['samples']), 1)

        self.assertEqual(data['samples'][0]['md5'],
                         '0f6f0c6b818f072a7a6f02441d00ac69')

        self.assertEqual(data['samples'][0]['md5'],
                         '0f6f0c6b818f072a7a6f02441d00ac69')

        self.assertEqual(data['samples'][0]['sha1'],
                         '39b8a7a0a99f6e2220cf60fd860923f9df3e8d01')

        self.assertEqual(data['samples'][0]['sha256'],
                         'e5b830bf3d82aba009244bff86d33b10a48b03f48ca52cd1d835f033e2b445e6')

        self.assertEqual(data['samples'][0]['size'], 12361)

    def test_get_analysis_data(self):
        retval = self.app.get('/api/1.0/samples/1/analysis/')
        self.assertEqual(retval.status_code, 200)

        data = json.loads(retval.data)

        self.assertIn('analyzeit', data.keys)
        self.assertIn('peinfo', data.keys)
        self.assertIn('strings', data.keys)

    def test_get_analyzeit_data(self):
        retval = self.app.get('/api/1.0/samples/1/analyzeit/')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertEqual(len(data), 1)

    def test_get_strings_data(self):
        retval = self.app.get('/api/1.0/samples/1/analysis/strings')
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertEqual(len(data), 1)

    def test_push_comments(self):
        retval = self.push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

    def test_get_comment(self):
        """
            This endpoint is used to get comments for a specific address
        """
        retval = self.push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

        retval = self.get_comment(address=0xDEADBEEF)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertIn(data['comments'][0]["data"], "TESTCOMMENT1")
        self.assertEqual(data['comments'][0]["address"], 0xDEADBEEF)

    def test_get_multiple_comments(self):
        retval = self.push_comment(address=0xDEADBEEF, comment="TESTCOMMENT1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

        retval = self.push_comment(address=0xBADF00D, comment="TESTCOMMENT2")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

        retval = self.get_comment()
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertEqual(len(data['comments']), 2)
        self.assertIn(data['comments'][0]["data"], "TESTCOMMENT1")
        self.assertEqual(data['comments'][0]["address"], 0xDEADBEEF)
        self.assertIn(data['comments'][1]["data"], "TESTCOMMENT2")
        self.assertEqual(data['comments'][1]["address"], 0xBADF00D)


    def test_multiple_comments_same_address(self):
        self.assertTrue(False)


    def test_push_name(self):
        retval = self.push_name(address=0xDEADBEEF, name="TESTNAME1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

    def test_get_names(self):
        """
            This endpoint is used to get comments for a specific address
        """
        retval = self.push_name(address=0xDEADBEEF, name="TESTNAME1")
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertTrue(data['result'])

        retval = self.get_name(address=0xDEADBEEF)
        self.assertEqual(retval.status_code, 200)
        data = json.loads(retval.data)
        self.assertIn(data['names'][0]["data"], "TESTNAME1")
        self.assertEqual(data['names'][0]["address"], 0xDEADBEEF)

if __name__ == '__main__':
    unittest.main()
