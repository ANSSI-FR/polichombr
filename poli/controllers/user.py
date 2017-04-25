"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        User management.
"""

import random
import time
from hashlib import sha256

from poli import app, db
from poli.models.user import User
from flask_security.utils import encrypt_password, verify_and_update_password
from poli import user_datastore


class UserController(object):
    """
        Operates on the User model
    """

    def create(self, username, password, completename=None):
        """
            Init the user model, and save it in DB
        """
        if User.query.filter_by(nickname=username).count() != 0:
            return False
        password = encrypt_password(password)
        user_datastore.create_user(nickname=username,
                                   password=password,
                                   completename=completename,
                                   active=False)

        myuser = User.query.filter_by(nickname=username).first()
        # TODO : manage API key with flask-login
        apikey_seed = str(random.randint(0, 0xFFFFFFFFFFFFFFFF))
        apikey_seed = apikey_seed + str(int(time.time()))
        apikey_seed = apikey_seed + sha256(username).hexdigest()
        apikey_seed = apikey_seed + sha256(password).hexdigest()
        apikey_seed = ''.join(random.sample(apikey_seed, len(apikey_seed)))
        myuser.api_key = sha256(apikey_seed).hexdigest()

        myuser.theme = "default"

        # the first user is active and admin
        if User.query.count() == 1:
            role = user_datastore.find_or_create_role("admin",
                                                      description="Administrator")
            if role is not None:
                user_datastore.add_role_to_user(myuser, role)
            else:
                app.logger.error("Cannot find and affect admin role to user")
            user_datastore.activate_user(myuser)

        db.session.commit()
        return True

    def add_role_to_user(uid, role):
        user = user_datastore.get_user(int(uid))
        user_datastore.add_role_to_user(user, role)

    @staticmethod
    def get_by_name(name):
        """
            Gets an user by its nickname.
        """
        user = User.query.filter_by(nickname=name)
        if user is None:
            return None
        return user.first()

    @staticmethod
    def set_theme(user, theme):
        """
            Gets an user's theme. No checks performed as it may change a lot.
        """
        user.theme = theme
        db.session.commit()
        return True

    @staticmethod
    def set_nick(user, nick):
        """
            Set's the user's login/nick.
        """
        if User.query.filter_by(nickname=nick).count() != 0:
            return False
        user.nickname = nick
        db.session.commit()
        return True

    @staticmethod
    def set_name(user, name):
        """
            Set's the user's complete name.
        """
        user.completename = name
        db.session.commit()
        return True

    @staticmethod
    def check_user_pass(user, passw):
        """
            Checks an user's password.
        """
        return verify_and_update_password(passw, user)

    def set_pass(self, user, passw):
        """
            Regenerate an user's password hash.
        """
        user.password = encrypt_password(passw)
        db.session.commit()
        return True

    @staticmethod
    def delete(user):
        """
            Removes an user from database.
        """
        db.session.delete(user)
        db.session.commit()
        return False

    @staticmethod
    def get_all():
        """
            Return all user objects.
        """
        return User.query.all()

    @staticmethod
    def get_by_id(user_id):
        """
            gets an user by its id. Used by the flask login manager.
        """
        return User.query.get(int(user_id))

    @staticmethod
    def deactivate(user_id):
        u = user_datastore.get_user(int(user_id))
        if u is not None:
            app.logger.debug("Deactivating user %s", u.nickname)
            user_datastore.deactivate_user(u)
            db.session.commit()
            return True
        return False

    @staticmethod
    def activate(user_id):
        u = User.query.get(int(user_id))
        if u is not None:
            user_datastore.activate_user(u)
            db.session.commit()
            return True
        return False
