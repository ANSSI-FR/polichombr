"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Routes for REST API
"""

from polichombr import api, app
from polichombr.models.yara_rule import YaraSchema
from polichombr.models.models import TLPLevel
from polichombr.models.user import User

from flask import jsonify, request, abort, make_response
from flask import Blueprint, current_app, g
from flask_security import current_user, login_required

apiview = Blueprint('apiview', __name__,
                    url_prefix=app.config['API_PATH'])


from polichombr.views.api_family import *
from polichombr.views.api_idaactions import *
from polichombr.views.api_sample import *


@apiview.before_request
def before_request():
    """
        Affects global variables for each request
    """
    g.user = current_user


@apiview.app_errorhandler(404)
def api_404_handler(error):
    """
        404 error handler for the whole API module
    """
    return jsonify(dict(error=404,
                        error_description="Resource not found")), 404


@apiview.app_errorhandler(500)
def api_500_handler(error):
    """
        Module wide, returned in case of server error
    """
    return jsonify({'error': 500,
                    'error_description': error.description,
                    }), 500


@apiview.errorhandler(400)
def api_400_handler(error):
    """
        module wide error handler, returned when there is an argument problem
    """
    return jsonify({'error': 400,
                    'error_description': error.description,
                    }), 400


@apiview.errorhandler(401)
def api_401_handler(error):
    """
        module wide error handler, returned when there is an argument problem
    """
    return jsonify({'error': 401,
                    'error_description': error.description,
                    }), 401


@apiview.route("/<path:invalid_path>", methods=['GET', 'POST', 'PATCH'])
def handle_unmatchable(*args, **kwargs):
    """
        Return a 404 when not finding an endpoint
    """
    abort(404)


@apiview.route('/api/')
@apiview.route('/')
def api_help():
    """
        Try to document the api.
        see docs/API.md for more informations
    """
    text = """
        See docs/API.md for more informations
    """
    response = make_response(text)
    return response


@apiview.route('/auth_token/', methods=["POST"])
def generate_token():
    """
        Generate a temporary token for using the API
    """
    data = request.json
    if not data:
        abort(400, "Missing JSON arguments")
    key = data['api_key']
    user = User.query.filter_by(api_key=key).first()
    if not user:
        current_app.logger.error("Invalid user trying to login")
        abort(401, "Invalid user")
    return jsonify({'token': user.get_auth_token()})


@apiview.route('/yaras/', methods=['GET'])
@login_required
def api_get_all_yaras():
    """
        Dump all the yaras
    """
    yaras = api.yaracontrol.get_all()
    schema = YaraSchema(many=True)
    return jsonify({'yara_rules': schema.dump(yaras).data})


@apiview.route('/yaras/', methods=['POST'])
@login_required
def api_create_yara():
    """
        Add a new yara
        @arg name: the yara name
        @arg rule: the full text of the rule
        @arg tlp_level: Optional, the sensibility of the rule.
            Default = TLP AMBER
    """
    tlp_level = None
    data = request.json
    name = data["name"]
    rule = data["rule"]
    if 'tlp_level' in list(data.keys()):
        tlp_level = data["tlp_level"]

    if tlp_level is None:
        tlp_level = TLPLevel.TLPAMBER

    result = api.yaracontrol.create(name, rule, tlp_level)
    if result is None or not result:
        abort(500, "Cannot create yara rule")
    return jsonify({"id": result.id})
