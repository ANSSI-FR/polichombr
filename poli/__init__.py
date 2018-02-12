"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Init flask app and the modules.
"""
from flask import Flask, abort


from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_marshmallow import Marshmallow
from flask_misaka import Misaka
from flask_security import Security, SQLAlchemyUserDatastore
from flask_bootstrap import StaticCDN


# Init bootstrap extension
bootstrap = Bootstrap()

# Init SQL extension
db = SQLAlchemy()
ma = Marshmallow()

# Init other extensions
misaka = Misaka()
security = Security()

# Init user management
from .models.user import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)


def create_app(config_filename):
    app = Flask(__name__)

    app.config.from_object(config_filename)
    app.logger.setLevel(app.config["LOG_LEVEL"])

    bootstrap.init_app(app)
    app.extensions['bootstrap']['cdns']['jquery'] = StaticCDN()

    db.init_app(app)
    ma.init_app(app)
    misaka.init_app(app)

    security.init_app(app, user_datastore)

    @app.login_manager.unauthorized_handler
    def abort_401():
        return abort(401)
    return app


app = create_app("config")

from .controllers.api import APIControl
api = APIControl()

from .views import apiview
from .views import webui

app.register_blueprint(apiview.apiview)
app.register_blueprint(webui.webuiview)

