#!/usr/bin/env python
"""
    This file is part of Polichombr.

    (c) 2017 ANSSI-FR


    Description:
        Creates the database
"""


import os.path
from polichombr import app, db

from polichombr.config import SQLALCHEMY_DATABASE_URI
from polichombr.config import SQLALCHEMY_MIGRATE_REPO
from migrate.versioning import api
from migrate import exceptions

try:
    with app.app_context():
        db.create_all()
except exceptions.DatabaseAlreadyControlledError:
    pass

if not os.path.exists(SQLALCHEMY_MIGRATE_REPO):
    api.create(SQLALCHEMY_MIGRATE_REPO, 'database repository')
    api.version_control(SQLALCHEMY_DATABASE_URI, SQLALCHEMY_MIGRATE_REPO)
else:
    api.version_control(SQLALCHEMY_DATABASE_URI,
                        SQLALCHEMY_MIGRATE_REPO,
                        api.version(SQLALCHEMY_MIGRATE_REPO))
