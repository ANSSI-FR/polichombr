#!/usr/bin/env python
import os
import poli
import unittest
import tempfile

from StringIO import StringIO

from poli.controllers.api import APIControl

from time import sleep


class MainTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.fname = tempfile.mkstemp()
        poli.app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+self.fname
        poli.app.config['TESTING'] = True
        poli.app.config['WTF_CSRF_ENABLED'] = False

        self.app = poli.app.test_client()
        with poli.app.app_context():
            poli.db.create_all()
            api = APIControl()
            api.usercontrol.create("john", "password")


    def tearDown(self):
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

    def create_family(self, fname="TOTO", level=1, parent_family=0):
        return self.app.post('/families/',
                             data=dict(familyname=fname,
                                       level=level,
                                       parentfamily=parent_family),
                             follow_redirects=True)

    def get_family(self, fid=0):
        return self.app.get('/family/'+str(fid) + '/', follow_redirects=True)

    def get_families(self):
        return self.app.get('/families/')

    def set_family_abstract(self, fid=1, abstract="TEST ABSTRACT"):
        return self.app.post('/family/'+str(fid)+'/',
                             data=dict(abstract=abstract),
                             follow_redirects=True)

    def set_sample_abstract(self,sid=1,abstract="TEST ABSTRACT"):
        retval = self.app.post("/sample/"+str(sid)+ "/",
                data = dict(abstract=abstract),
                follow_redirects=True)
        return retval

    def create_sample(self):
        with open("tests/example_pe.bin", "rb") as hfile:
            data = StringIO(hfile.read())

        self.login("john", "password")
        retval = self.app.post("/samples/",
                           content_type='multipart/form-data',
                           data=dict(
                               {'file': (data, "toto")},
                               level=1, family=0),
                           follow_redirects=True)

        # XXX : put a callback here to be notified when the analysis is ended
        sleep(3)
        return retval

    def add_sample_to_family(self, sid=1, fid=1):
        self.login("john", "password")
        retval = self.app.post("/sample/"+str(sid)+ "/",
                data = dict(parentfamily=fid),
                follow_redirects=True)
        return retval

    def register_user(self, name, password):
        retval = self.app.post("/register/",
                data = dict(username=name,
                    password=password,
                    completename=name,
                    rpt_pass=password,
                    userregister="Submit"),
                follow_redirects=True)
        return retval


    def test_create_sample(self):
        retval = self.create_sample()
        self.assertTrue(retval)

    def logout(self):
        return self.app.get("/logout/",
                            follow_redirects=True)

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
        retval = self.app.post("/user/2/activate", follow_redirects=True)
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
        retval = self.app.post("/user/2/activate", follow_redirects=True)

        self.logout()

        # test that normal user cannot access admin
        retval = self.login("notadmin", "password")
        self.assertNotIn("href=\"/admin\"", retval.data)

        retval = self.app.get("/admin/", follow_redirects=True)
        self.assertNotIn("Admin", retval.data)

    def test_running(self):
        retval = self.app.get('/')

        self.assertIn("<body>", retval.data)
        self.assertIn("</body>", retval.data)

    def test_family_creation(self):
        self.login("john", "password")
        retval = self.create_family()
        self.assertIn('<a class="btn btn-primary" href="/family/1">TOTO', retval.data)

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
        self.login("john", "password")
        retval = self.create_family("THISISATEST", level=1)
        retval = self.get_family(1)
        self.assertIn('TLP White', retval.data)

        retval = self.create_family("THISISATEST2", level=2)
        retval = self.get_family(2)
        self.assertIn('TLP Green', retval.data)

        retval = self.create_family("THISISATEST3", level=3)
        retval = self.get_family(3)
        self.assertIn('TLP Amber', retval.data)

        retval = self.create_family("THISISATEST4", level=4)
        retval = self.get_family(4)
        self.assertIn('TLP Red', retval.data)

        retval = self.create_family("THISISATEST5", level=5)
        retval = self.get_family(5)
        self.assertIn('TLP Black', retval.data)

    def test_family_abstract(self):
        self.login("john", "password")
        self.create_family()
        retval = self.set_family_abstract(fid=1, abstract="TEST ABSTRACT")
        self.assertIn("TEST ABSTRACT", retval.data)

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


    def test_sample_hashes(self):
        self.login("john", "password")
        self.create_sample()
        retval = self.app.get("/sample/1/")
        self.assertIn("0f6f0c6b818f072a7a6f02441d00ac69", retval.data)
        self.assertIn("39b8a7a0a99f6e2220cf60fd860923f9df3e8d01", retval.data)
        self.assertIn("e5b830bf3d82aba009244bff86d33b10a48b03f48ca52cd1d835f033e2b445e6", retval.data)

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

if __name__ == '__main__':
    unittest.main()
