"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        User data model.
        Dependant on Flask-Login for authentication
"""

from poli import db, ma
from flask_security import UserMixin, RoleMixin

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

roles_users = db.Table('roles_users',
                       db.Column('user_id',
                                 db.Integer(),
                                 db.ForeignKey('user.id')),
                       db.Column('role_id',
                                 db.Integer(),
                                 db.ForeignKey('auth_role.id')))


class Role(db.Model, RoleMixin):
    __tablename__ = 'auth_role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String())

    def __init__(self, name, description):
        self.name = name
        self.description = description

    def setDescription(self, description):
        self.description = description

    def toString(self):
        return {"name": self.name, "description": self.description}

    def __repr__(self):
        return '<Role %r>' % self.name


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
    # Password
    password = db.Column(db.String())
    api_key = db.Column(db.String())
    roles = db.relationship('Role',
                            secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    current_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean(), default=False)

    def get_id(self):
        return self.id

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
