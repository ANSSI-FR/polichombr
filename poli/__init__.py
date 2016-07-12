"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Init flask app and the modules.
"""

from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_misaka import Misaka

app = Flask(__name__)

app.config.from_object('config')


# Init bootstrap extension
Bootstrap(app)


# Init SQL extension
db = SQLAlchemy(app)
ma = Marshmallow(app)
Misaka(app)
# Init login manager extension
login_manager = LoginManager()
login_manager.init_app(app)

from poli.controllers.api import APIControl

api = APIControl()

from poli.views import webui, apiview
