"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        User data model.
        Dependant on Flask-Login for authentication
"""

from poli import db, ma
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


usersample = db.Table('usersample',
                      db.Column('user_id', db.Integer,
                                db.ForeignKey('user.id')),
                      db.Column('sample_id', db.Integer,
                                db.ForeignKey('sample.id'))
                      )

userfamily = db.Table('userfamily',
                      db.Column('user_id', db.Integer,
                                db.ForeignKey('user.id')),
                      db.Column('family_id', db.Integer,
                                db.ForeignKey('family.id'))
                      )


class UserPrivilege:
    """
    User privileges. Not used for now.
    """
    (
        ADMIN,
        PRIVILEGED,
        REGULAR
    ) = range(1, 4)

    @classmethod
    def tostring(cls, val):
        for k, v in vars(cls).iteritems():
            if v == val:
                return k
        return ""

    @classmethod
    def fromstring(cls, s):
        return getattr(cls, s, None)


class User(db.Model, UserMixin):
    """
    User model.
    """
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    # N-N relationships
    samples = db.relationship('Sample', secondary=usersample,
                              backref=db.backref('users', lazy="dynamic"))
    families = db.relationship('Family', secondary=userfamily,
                               backref=db.backref('users', lazy="dynamic"))
    # Login
    nickname = db.Column(db.String(), index=True, unique=True)
    # Complete user name
    completename = db.Column(db.String(), index=True, unique=True)
    theme = db.Column(db.String())
    # User's email (not used for now)
    email = db.Column(db.String(), index=True, unique=True)
    # User's most loved pokemon!!!
    poke_id = db.Column(db.Integer())
    # Password
    password = db.Column(db.String())
    api_key = db.Column(db.String())
    # Priv level
    privilege_level = db.Column(db.Integer())

    # Flask-login related methods. All methods return True because multiple
    # logins are authorized.
    def get_id(self):
        return self.id

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def __repr__(self):
        return '<User %r>' % (self.nickname)


class UserSchema(ma.ModelSchema):
    """
    Schema representation.
    """
    class Meta:
        fields = (
            'id',
            'nickname'
        )
