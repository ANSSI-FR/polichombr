"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        User management.
"""

from hashlib import sha256
import uuid

from polichombr import app, db
from polichombr.models.user import User
from polichombr import user_datastore

from flask_security.utils import hash_password, verify_and_update_password


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
        password = hash_password(password)
        user_datastore.create_user(nickname=username,
                                   password=password,
                                   completename=completename,
                                   active=False)

        myuser = User.query.filter_by(nickname=username).first()
        myuser.theme = "default"

        myuser.api_key = self.generate_api_key(username, password)

        # the first user is active and admin
        if User.query.count() == 1:
            self.manage_admin_role(myuser.id)
            user_datastore.activate_user(myuser)
        db.session.commit()
        return True

    @staticmethod
    def generate_api_key(username, password):
        """
            Generate a random API key for the user
        """
        seed = str(uuid.uuid4())
        seed = u'%s%s%s' % (seed, username, password)
        api_key = sha256(seed.encode('utf-8')).hexdigest()

        return api_key

    @classmethod
    def manage_admin_role(cls, uid):
        """
            Toggle admin roles for given uid
        """
        user = user_datastore.get_user(int(uid))

        role = user_datastore.find_or_create_role(
            "admin", description="Administrator")
        if role is not None:
            if role not in user.roles:
                app.logger.debug("Giving admin privileges to user %s" %
                                 (user.nickname))
                user_datastore.add_role_to_user(user, role)
            else:
                app.logger.debug("Removing admin privileges to user %s" %
                                 (user.nickname))
                user_datastore.remove_role_from_user(user, role)

        else:
            app.logger.error("Cannot find and affect admin role to user")
            return False
        db.session.commit()
        return True

    @classmethod
    def renew_api_key(cls, user):
        """
            Generate a new api_key for the user
        """
        new_key = cls.generate_api_key(user.nickname, user.password)
        user.api_key = new_key
        db.session.commit()
        return True

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

    @staticmethod
    def set_pass(user, passw):
        """
            Regenerate an user's password hash.
        """
        user.password = hash_password(passw)
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
        """
            Disable access for a user
        """
        user = user_datastore.get_user(int(user_id))
        if user is not None:
            app.logger.debug("Deactivating user %s", user.nickname)
            user_datastore.deactivate_user(user)
            db.session.commit()
            return True
        return False

    @staticmethod
    def activate(user_id):
        """
            Toggle user activation status
        """
        user = User.query.get(int(user_id))
        if user is not None:
            user_datastore.activate_user(user)
            db.session.commit()
            return True
        return False
