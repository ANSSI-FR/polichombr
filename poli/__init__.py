"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Init flask app and the modules.
"""

from flask import Flask
from flask import Blueprint

from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_marshmallow import Marshmallow
from flask_misaka import Misaka
from flask_security import Security, SQLAlchemyUserDatastore
from flask_bootstrap import StaticCDN


app = Flask(__name__)

app.config.from_object('config')
app.logger.setLevel(app.config["LOG_LEVEL"])

# Init bootstrap extension
Bootstrap(app)
app.extensions['bootstrap']['cdns']['jquery'] = StaticCDN()

# Init SQL extension
db = SQLAlchemy(app)
ma = Marshmallow(app)
Misaka(app)

# Init user management
from poli.models.user import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

from poli.controllers.api import APIControl

api = APIControl()


apiview = Blueprint('apiview', __name__, url_prefix=app.config['API_PATH'])

from poli.views import webui
from poli.views import apiview as view

app.register_blueprint(apiview)
