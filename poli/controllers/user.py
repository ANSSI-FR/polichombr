import random
import time
from hashlib import sha256

from poli import app, db
from poli import login_manager
from poli.models.user import User
from werkzeug.security import generate_password_hash, check_password_hash


class UserController(object):
    """
        Operates on the User model
    """

    def create(self, username, password, completename=None, poke_id=None):
        """
            Init the user model, and save it in DB
        """
        if User.query.filter_by(nickname=username).count() != 0:
            return None
        myuser = User()

        # TODO : manage API key with flask-login
        apikey_seed = str(random.randint(0, 0xFFFFFFFFFFFFFFFF))
        apikey_seed = apikey_seed + str(int(time.time()))
        apikey_seed = apikey_seed + sha256(username).hexdigest()
        apikey_seed = apikey_seed + sha256(password).hexdigest()
        apikey_seed = ''.join(random.sample(apikey_seed, len(apikey_seed)))
        myuser.api_key = sha256(apikey_seed).hexdigest()

        myuser.nickname = username
        myuser.completename = completename
        myuser.theme = "default"
        myuser.password = generate_password_hash(password)
        db.session.add(myuser)
        db.session.commit()
        if poke_id is None:
            # So you did not choose your favorite pokemon? So you're not a true
            # pokemon trainer, you will never have a REAL pokemon (0-151),
            # muahahahahaha!
            self.set_poke(myuser, random.randint(152, 721))
        else:
            self.set_poke(myuser, poke_id)
        return myuser

    @staticmethod
    def get_by_key(key):
        """
            Gets the user by its api key.
            TODO: replace by @login_manager.request_loader.
        """
        user = User.query.filter_by(api_key=key)
        if user is None:
            return None
        return user.first()

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
    def set_poke(user, poke_id):
        """
            Set's the user pokemon ID.
        """
        if poke_id > 721 or poke_id < 0:
            poke_id = random.randint(152, 721)
        user.poke_id = poke_id
        db.session.add(user)
        db.session.commit()
        return True

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
        return check_password_hash(user.password, passw)

    @staticmethod
    def set_pass(user, passw):
        """
            Regenerate an user's password hash.
        """
        user.password = generate_password_hash(passw)
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
    @login_manager.user_loader
    def get_by_id(user_id):
        """
            gets an user by its id. Used by the flask login manager.
        """
        return User.query.get(int(user_id))
