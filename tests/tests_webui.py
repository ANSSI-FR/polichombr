#!/usr/bin/env python

"""
        This file is part of Polichombr.
            (c) ANSSI-FR 2018

        Description:
            Test cases for the web interface
"""

import unittest
import tempfile
from StringIO import StringIO
from time import sleep

import os
import io
import json

import poli
from poli.controllers.api import APIControl

from zipfile import ZipFile


class WebUIBaseClass(unittest.TestCase):
    """
        Implement the utility functions inherited by the tests cases
    """
    def setUp(self):
        self.db_fd, self.fname = tempfile.mkstemp()
        poli.app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + self.fname
        poli.app.config['TESTING'] = True
        poli.app.config['WTF_CSRF_ENABLED'] = False

        self.app = poli.app.test_client()
        with poli.app.app_context():
            poli.db.create_all()
            api = APIControl()
            api.usercontrol.create("john", "password")

    def tearDown(self):
        with poli.app.app_context():
            poli.db.session.remove()
            poli.db.drop_all()
        os.close(self.db_fd)
        os.unlink(self.fname)

    def login(self, username, password):
        return self.app.post("/login/",
                             data=dict(
                                 username=username,
                                 password=password),
                             follow_redirects=True)

    def logout(self):
        return self.app.get("/logout/",
                            follow_redirects=True)

    def create_family(self, fname="TOTO", level=1, parent_family=0):
        return self.app.post('/families/',
                             data=dict(familyname=fname,
                                       level=level,
                                       parentfamily=parent_family),
                             follow_redirects=True)

    def get_family(self, fid=0):
        return self.app.get('/family/' + str(fid) + '/', follow_redirects=True)

    def get_families(self):
        return self.app.get('/families/')

    def set_family_abstract(self, fid=1, abstract="TEST ABSTRACT"):
        return self.app.post('/family/' + str(fid) + '/',
                             data=dict(abstract=abstract),
                             follow_redirects=True)

    def set_family_tlp(self, fid, level=1):
        data = dict(level=level, item_id=None)
        retval = self.app.post("/family/" + str(fid) + "/", data=data,
                               follow_redirects=True)
        return retval

    def set_sample_abstract(self, sid=1, abstract="TEST ABSTRACT"):
        retval = self.app.post("/sample/" + str(sid) + "/",
                               data=dict(abstract=abstract),
                               follow_redirects=True)
        return retval

    def create_sample(self):
        with open("tests/example_pe.bin", "rb") as hfile:
            data = StringIO(hfile.read())

        self.login("john", "password")
        retval = self.app.post("/samples/",
                               data=dict(
                                   {'files': (data, "toto")},
                                   level=1, family=0),
                               follow_redirects=True)

        # XXX : put a callback here to be notified when the analysis is ended
        sleep(2)
        return retval

    def create_sample_from_machex(self):
        with open("tests/example_pe.machex", "rb") as hfile:
            data = StringIO(hfile.read())

        self.login("john", "password")
        retval = self.app.post("/import/",
                               data=dict(
                                   {'file': (data, "toto")},
                                   level=1, family=0),
                               follow_redirects=True)
        return retval

    def add_sample_to_family(self, sid=1, fid=1):
        self.login("john", "password")
        retval = self.app.post("/sample/" + str(sid) + "/",
                               data=dict(parentfamily=fid),
                               follow_redirects=True)
        return retval

    def remove_sample_from_family(self, sid=1, fid=1):
        self.login("john", "password")
        retval = self.app.get("/sample/" + str(sid) + "/removefam/" + str(fid),
                              follow_redirects=True)
        return retval

    def register_user(self, name, password):
        retval = self.app.post("/register/",
                               data=dict(username=name,
                                         password=password,
                                         completename=name,
                                         rpt_pass=password,
                                         userregister="Submit"),
                               follow_redirects=True)
        return retval


class WebUIBaseTests(WebUIBaseClass):
    def test_create_sample(self):
        retval = self.create_sample()
        self.assertTrue(retval)

    def test_running(self):
        retval = self.app.get('/')

        self.assertIn("<body>", retval.data)
        self.assertIn("</body>", retval.data)

    def test_download_skelenox(self):
        self.login("john", "password")
        retval = self.app.get("/skelenox/")
        self.assertEqual(retval.status_code, 200)
        data = io.BytesIO(retval.data)

        toto = ZipFile(data)
        self.assertEqual("skelenox.py", toto.namelist()[0])
        self.assertEqual("skelsettings.json", toto.namelist()[1])

        skel_config = toto.open("skelsettings.json")
        skel_config = json.loads(skel_config.read())

        self.assertEqual("localhost", skel_config["poli_server"])
        # XXX activate after 08c1dfa0ea4d6f783a452777fca64e65ec0b4c11
        #self.assertEqual('5000', skel_config["poli_port"])
        #self.assertEqual('/api/1.0/', skel_config["poli_remote_path"])

    def test_yara_rule_forms(self):
        """
            Try to create, rename and change TLP level of a yara rule
        """
        self.login("john", "password")
        self.create_sample()
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""

        data = dict(yara_name="TEST_YARA",
                    yara_raw=rule_text,
                    yara_tlp=1)
        retval = self.app.post("/signatures/", data=data)

        self.assertEqual(retval.status_code, 200)
        self.assertIn("<h3 class=\"panel-title\">TEST_YARA</h3>", retval.data)
        self.assertIn("$1 = {4D 5A}", retval.data)

        # test tlp change for the rule
        data = dict(item_id=1,
                    level=4)
        retval = self.app.post("/signatures/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn("<span class=\"text-danger\">TLP RED", retval.data)

        # test rule renaming
        data = dict(item_id=1,
                    newname="TEST_YARA_RENAMED")
        retval = self.app.post("/signatures/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn(
            "<h3 class=\"panel-title\">TEST_YARA_RENAMED</h3>", retval.data)

        # test wrong yara format

        data = dict(yara_name="WRONG YARA",
                    yara_raw=rule_text.replace("strings", "wrong_string"),
                    yara_tlp=1)
        retval = self.app.post("/signatures/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn("Error during yara creation", retval.data)

    def test_delete_yara(self):
        self.login("john", "password")
        self.create_sample()
        rule_text = """rule toto{
            strings:
                $1 = {4D 5A}
            condition:
                $1 at 0
        }"""

        data = dict(yara_name="TEST_YARA",
                    yara_raw=rule_text,
                    yara_tlp=1)
        retval = self.app.post("/signatures/", data=data)

        retval = self.app.get("/signatures/delete/"+"1")
        self.assertEqual(retval.status_code, 302)

        retval = self.app.get("/signatures/")
        self.assertIn("alert alert-success alert-dismissible", retval.data)
        self.assertIn("Deleted rule TEST_YARA", retval.data)


class WebUIFamilyTestCase(WebUIBaseClass):
    """
        Tests functionatities related to families
    """
    @unittest.skip("waiting for JS debugging")
    def test_family_creation(self):
        self.login("john", "password")
        retval = self.create_family()
        self.assertIn(
            '<a class="btn btn-primary" href="/family/1">TOTO', retval.data)

        retval = self.create_family("TITI")
        retval = self.get_families()
        self.assertIn('<a class="btn btn-primary" href="/family/1">TOTO',
                      retval.data)
        self.assertIn('<a class="btn btn-primary" href="/family/2">TITI',
                      retval.data)

    def test_family_display_simple(self):
        self.login("john", "password")
        retval = self.create_family("THISISATEST", level=1)
        retval = self.get_family(1)  # we only have a unique family
        self.assertIn('THISISATEST', retval.data)

    def test_family_display_TLP(self):
        """
            This tests both display and TLP change,
            as a family cannot currently be created with a custom TLP
        """
        self.login("john", "password")
        retval = self.create_family("THISISATEST", level=1)
        retval = self.set_family_tlp(fid=1, level=1)
        retval = self.get_family(1)
        self.assertIn('TLP WHITE', retval.data)

        retval = self.create_family("THISISATEST2", level=2)
        retval = self.set_family_tlp(fid=2, level=2)
        retval = self.get_family(2)
        self.assertIn('TLP GREEN', retval.data)

        retval = self.create_family("THISISATEST3", level=3)
        retval = self.set_family_tlp(fid=3, level=3)
        retval = self.get_family(3)
        self.assertIn('TLP AMBER', retval.data)

        retval = self.create_family("THISISATEST4", level=4)
        retval = self.set_family_tlp(fid=4, level=4)
        retval = self.get_family(4)
        self.assertIn('TLP RED', retval.data)

        retval = self.create_family("THISISATEST5", level=5)
        retval = self.set_family_tlp(fid=5, level=5)
        retval = self.get_family(5)
        self.assertIn('TLP BLACK', retval.data)

    def test_family_abstract(self):
        self.login("john", "password")
        self.create_family()
        retval = self.set_family_abstract(fid=1, abstract="TEST ABSTRACT")
        self.assertIn("TEST ABSTRACT", retval.data)

    def test_family_deletion(self):
        self.login("john", "password")
        self.create_family()

        retval = self.app.get("/family/1/delete/")
        self.assertEqual(retval.status_code, 302)

        retval = self.get_families()
        # Is the family deleted?
        self.assertNotIn("TOTO", retval.data)

        # Is the user flashed about family deletion?
        self.assertIn("Deleted family", retval.data)

    def test_family_sample(self):
        self.login("john", "password")
        self.create_family(fname="TEST FAMILY FOR SAMPLE")
        self.create_sample()
        retval = self.add_sample_to_family()

        # test if the family is in the sample view
        self.assertTrue(retval)
        retval = self.app.get('/sample/1/')
        self.assertIn('TEST FAMILY FOR SAMPLE', retval.data)

        # test if the sample is linked in the family view
        retval = self.app.get('/family/1/')
        self.assertIn('0f6f0c6b818f072a7a6f02441d00ac69', retval.data)

    def test_sample_multiple_family(self):
        self.login("john", "password")
        self.create_family(fname="TEST FAMILY FOR SAMPLE")
        self.create_family(fname="SECOND FAMILY FOR SAMPLE")
        self.create_sample()
        retval = self.add_sample_to_family(1, 1)
        self.assertTrue(retval)

        retval = self.add_sample_to_family(1, 2)
        self.assertTrue(retval)

        # test if the family is in the sample view
        retval = self.app.get('/sample/1/')
        self.assertIn('TEST FAMILY FOR SAMPLE', retval.data)
        self.assertIn('SECOND FAMILY FOR SAMPLE', retval.data)

        # test if the sample is linked in the family view
        retval = self.get_family(1)
        self.assertIn('0f6f0c6b818f072a7a6f02441d00ac69', retval.data)

        retval = self.get_family(2)
        self.assertIn('0f6f0c6b818f072a7a6f02441d00ac69', retval.data)


class WebUIUserManagementTestCase(WebUIBaseClass):
    """
        User registration, admin functions,
        login and logout tests
    """
    def test_login_func(self):
        # Test correct login
        retval = self.login("john", "password")
        self.assertNotIn("error", retval.data)
        self.assertNotIn("href=\"/login\"", retval.data)

    def test_logout(self):
        # Test logout
        retval = self.login("john", "password")
        retval = self.logout()
        self.assertNotIn("error", retval.data)
        self.assertIn("href=\"/login/\"", retval.data)

    def test_wrong_login(self):
        # test wrong login
        retval = self.login("IncorrectUser", "password1")
        self.assertIn("href=\"/login/\"", retval.data)

        retval = self.login("john", "password1")
        self.assertIn("href=\"/login/\"", retval.data)

    def test_register(self):
        retval = self.register_user("SomeUserName", "password2")
        self.assertEqual(retval.status_code, 200)

        # the new user is not activated, so it cannot login
        retval = self.login("john", "password")
        retval = self.app.post("/user/2/activate/", follow_redirects=True)
        self.assertEqual(retval.status_code, 200)
        self.logout()
        retval = self.login("SomeUserName", "password2")
        self.assertIn("logout", retval.data)

    def test_admin(self):
        # test normal user registration
        retval = self.register_user("notadmin", "password")
        self.assertEqual(retval.status_code, 200)

        # test admin panel access
        retval = self.login("john", "password")
        self.assertIn("href=\"/admin\"", retval.data)

        # test the availability of user management
        retval = self.app.get("/admin/", follow_redirects=True)
        self.assertEqual(retval.status_code, 200)
        self.assertIn("notadmin", retval.data)
        # don't forget to activate user 2
        retval = self.app.post("/user/2/activate/", follow_redirects=True)

        self.logout()

        # test that normal user cannot access admin
        retval = self.login("notadmin", "password")
        self.assertNotIn("href=\"/admin\"", retval.data)

        retval = self.app.get("/admin/", follow_redirects=True)
        self.assertNotIn("Admin", retval.data)

    def test_giving_admin_rights(self):
        retval = self.register_user("notadmin", "password")
        self.logout()

        retval = self.login("john", "password")
        retval = self.app.post("/user/2/activate/", follow_redirects=True)
        retval = self.app.post("/user/2/admin/", follow_redirects=True)
        self.assertEqual(retval.status_code, 200)

        self.assertNotIn("Cannot give admin to user", retval.data)
        self.assertIn("is now an admin", retval.data)

        self.logout()

        retval = self.login("notadmin", "password")

        retval = self.app.get("/", follow_redirects=True)
        self.assertIn("notadmin", retval.data)
        self.assertIn("Admin", retval.data)
        retval = self.app.get("/admin/", follow_redirects=True)
        self.assertEqual(retval.status_code, 200)
        self.assertIn("/admin", retval.data)

    def test_user_password(self):
        retval = self.login("john", "password")

        retval = self.app.get("/user/1/")
        self.assertEqual(retval.status_code, 200)
        self.assertIn('<div class="form-group  required"><label class="control-label" for="password">New password</label>', retval.data)

        data = {"oldpass": "password",
                "password": "newpassword",
                "rpt_pass": "newpassword"}

        retval = self.app.post("/user/1/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn("Changed user password", retval.data)

        self.logout()

        # Login with the new password
        retval = self.login("john", "newpassword")
        self.assertNotIn("error", retval.data)
        self.assertNotIn("href=\"/login\"", retval.data)

        self.logout()

        # Login with the old password, should fail
        retval = self.login("john", "password")
        self.assertIn("Cannot login...", retval.data)
        self.assertIn("href=\"/login", retval.data)


class WebUISampleManagementTests(WebUIBaseClass):
    """
        Sample tests
    """
    def test_sample_hashes(self):
        self.login("john", "password")
        self.create_sample()
        retval = self.app.get("/sample/1/")
        self.assertIn("0f6f0c6b818f072a7a6f02441d00ac69", retval.data)
        self.assertIn("39b8a7a0a99f6e2220cf60fd860923f9df3e8d01", retval.data)
        self.assertIn(
            "e5b830bf3d82aba009244bff86d33b10a48b03f48ca52cd1d835f033e2b445e6", retval.data)

    def test_sample_abstract(self):
        self.login("john", "password")
        self.create_sample()
        retval = self.app.get("/sample/1/")
        self.assertIn("My beautiful sample", retval.data)

        ret_val = self.set_sample_abstract(1, "TESTABSTRACT")
        self.assertTrue(ret_val)
        retval = self.app.get("/sample/1/")
        self.assertIn("TESTABSTRACT", retval.data)

    def test_double_sample_abstract(self):
        self.login("john", "password")
        self.create_sample()
        retval = self.app.get("/sample/1/")
        self.assertIn("My beautiful sample", retval.data)

        ret_val = self.set_sample_abstract(1, "TESTABSTRACT")
        self.assertTrue(ret_val)
        retval = self.app.get("/sample/1/")
        self.assertIn("TESTABSTRACT", retval.data)
        self.assertNotIn("My beautiful sample", retval.data)

        ret_val = self.set_sample_abstract(1, "TEST DOUBLE ABSTRACT")
        self.assertTrue(ret_val)
        retval = self.app.get("/sample/1/")
        self.assertIn("TEST DOUBLE ABSTRACT", retval.data)
        self.assertNotIn("TESTABSTRACT", retval.data)
        self.assertNotIn("My beautiful sample", retval.data)

    def test_sample_metadata(self):
        self.login("john", "password")
        self.create_sample()

        retval = self.app.get("/sample/1/")
        self.assertIn("12.1 KiB", retval.data)
        # TODO: complete this!

    def test_search_hashes(self):
        self.login("john", "password")
        self.create_sample()

        data = {"hneedle": "0f6f0c6b818f072a7a6f02441d00ac69"}
        retval = self.app.post("search/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn('<a href="/sample/1/">', retval.data)
        self.assertIn("0f6f0c6b818f072a7a6f02441d00ac69</label>", retval.data)

        # test with uppercase in the hash
        data = {"hneedle": "0F6F0C6B818f072a7a6f02441d00ac69"}
        retval = self.app.post("search/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertIn('<a href="/sample/1/">', retval.data)
        self.assertIn("0f6f0c6b818f072a7a6f02441d00ac69</label>", retval.data)

        # test with hash with a wrong length
        data = {"hneedle": "ABCD0F6F0C6B818f072a7a6f02441d00ac69"}
        retval = self.app.post("search/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertNotIn('<a href="/sample/1/">', retval.data)
        self.assertNotIn(
            "0f6f0c6b818f072a7a6f02441d00ac69</label>", retval.data)

        # test with wrong hash
        data = {"hneedle": "DEAD0c6b818f072a7a6f02441d00ac69"}
        retval = self.app.post("search/", data=data)
        self.assertEqual(retval.status_code, 200)
        self.assertNotIn('<a href="/sample/1/">', retval.data)
        self.assertNotIn(
            "0f6f0c6b818f072a7a6f02441d00ac69</label>", retval.data)

    def test_search_full_text(self):
        """
            FT search function
        """
        self.login("john", "password")
        self.create_sample()

        data = {"fneedle": "MessageBoxA"}
        retval = self.app.post("search/", data=data)
        self.assertEqual(retval.status_code, 200)
        # XXX this won't work until the analysis data is correctly commited in the tests...
        #self.assertIn("/sample/1", retval.data)

    def test_sample_deletion(self):
        """
            Delete a sample
        """
        self.login("john", "password")
        self.create_sample()

        retval = self.app.get("/sample/1/delete/")
        self.assertEqual(302, retval.status_code)
        self.assertIn("http://localhost/index", retval.headers["Location"])

        retval = self.app.get("/sample/1/")
        self.assertEqual(404, retval.status_code)

        retval = self.app.get("/sample/1/delete/")
        self.assertEqual(404, retval.status_code)

#     def test_machex_import(self):
        # """
        # XXX This will crash.
        # """
        # retval = self.create_sample_from_machex()
        # self.assertEqual(retval.status_code, 200)

    def test_machex_export(self):
        self.login("john", "password")
        self.create_sample()

        data = dict(machocfull=True,
                    fmachoc=True,
                    fnames=True,
                    analysis_data=True,
                    abstracts=True,
                    metadata=True,
                    estrings=True)

        retval = self.app.post("/samples/1/machexport/", data=data)
        self.assertEqual(retval.status_code, 200)

        data = json.loads(retval.data)

        self.assertIn("0f6f0c6b818f072a7a6f02441d00ac69", data["md5"])
        self.assertEqual(12361, data["size"])
        self.assertEqual(len(data["filenames"]), 1)

    def test_remove_sample_from_family(self):
        self.login("john", "password")
        self.create_sample()
        self.create_family()
        self.add_sample_to_family()

        retval = self.remove_sample_from_family(1, 1)
        self.assertEqual(retval.status_code, 200)

        retval = self.get_family(1)
        self.assertNotIn("0f6f0c6b818f072a7a6f02441d00ac69", retval.data)

    def test_disassembly_view(self):
        """
        """
        self.login("john", "password")
        self.create_sample()

        retval = self.app.get("/sample/1/disassemble/0x401000")

        self.assertEqual(retval.status_code, 200)
        self.assertIn(
            '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"', retval.data)
        self.assertIn("40100fh mov dx, 2", retval.data)
        self.assertIn("401000h mov eax, 1 ; Top function : entry", retval.data)

        # XXX maybe test for getting the AnalyzeIt comments

    def test_sample_download(self):
        """
            The download process is a redirection to the correct API endpoint
        """
        self.login("john", "password")
        self.create_sample()

        retval = self.app.get("/sample/1/download/")
        self.assertEqual(retval.status_code, 302)
        self.assertIn("/api/1.0/samples/1/download/",
                      retval.headers["Location"])

    def test_machoc_diff(self):
        """
            Machoc diffing
            TODO: test posting and renaming
        """
        self.login("john", "password")
        self.create_sample()

        with open("tests/example_pe.bin", "rb") as hfile:
            data = StringIO(hfile.read()[:-10])

        retval = self.app.post("/samples/",
                               data=dict(
                                   {'files': (data, "toto")},
                                   level=1, family=0),
                               follow_redirects=True)

        retval = self.app.get("/machocdiff/1/2/")

        self.assertEqual(retval.status_code, 200)

    def test_checklists(self):
        self.login("john", "password")
        retval = self.app.get("/settings/")
        self.assertEqual(retval.status_code, 200)

        data = dict(title="Test checklist", description="Test Checklist content")

        retval = self.app.post("/settings/", data=data)
        self.assertEqual(retval.status_code, 200)

        self.create_sample()
        retval = self.app.get("/sample/1/")

        self.assertIn("Test Checklist content", retval.data)
        self.assertIn('panel-danger"', retval.data)
        self.assertIn('href="/sample/1/checkfield/1">toggle</a>', retval.data)

        retval = self.app.get("/sample/1/checkfield/1/")
        self.assertEqual(retval.status_code, 302)

        retval = self.app.get("/sample/1/")
        self.assertNotIn('panel-danger"', retval.data)
        self.assertIn('href="/sample/1/checkfield/1">toggle</a>', retval.data)

        retval = self.app.get("/settings/deletechecklist/1/")

        self.assertEqual(retval.status_code, 302)
        retval = self.app.get("/settings/")
        self.assertNotIn("Test Checklist content", retval.data)


if __name__ == '__main__':
    unittest.main()
