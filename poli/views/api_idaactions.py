"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        API endpoints for managing IDA Actions attached to a sample
"""
import datetime

from flask import jsonify, request, abort, current_app
from flask_security import login_required, current_user

from poli import api
from poli.views.apiview import apiview
from poli.models.sample import FunctionInfoSchema


def get_filter_arguments(mrequest):
    """
        Get timestamp and address from request
    """
    data = mrequest.args
    cur_timestamp, addr = None, None
    if data is not None:
        if 'timestamp' in data.keys():
            cur_timestamp = data['timestamp']
            form = "%Y-%m-%dT%H:%M:%S.%f"
            try:
                cur_timestamp = datetime.datetime.strptime(cur_timestamp, form)
            except ValueError:
                abort(500, "Wrong timestamp format")
        if 'addr' in data.keys():
            addr = int(data['addr'], 16)
    return cur_timestamp, addr


@apiview.route('/samples/<int:sid>/idaactions/', methods=['GET'])
@login_required
def api_get_idaactions_updates(sid):
    """
        Get all actions for a sample
    """
    timestamp = datetime.datetime.now()

    actions = api.idacontrol.get_all(sid=sid, timestamp=timestamp)

    form = "%Y-%m-%dT%H:%M:%S.%f"
    str_time = datetime.datetime.strftime(timestamp, form)

    return jsonify({'idaactions': actions,
                    'timestamp': str_time})


@apiview.route('/samples/<int:sid>/functions/', methods=['GET'])
@login_required
def api_get_sample_functions(sid):
    """
        Return all functions info for a sample
    """
    functions = api.samplecontrol.get_functions(sid)
    schema = FunctionInfoSchema(many=True)
    return jsonify(schema.dump(functions).data)


@apiview.route('/samples/<int:sid>/functions/proposednames/', methods=['GET'])
@login_required
def api_suggest_func_names(sid):
    """
        Returns a dictionary containing proposed function names
        based on machoc matches.
    """
    sample = api.get_elem_by_type("sample", sid)
    proposed_funcs = api.samplecontrol.get_proposed_funcnames(sample)
    return jsonify({'functions': proposed_funcs})


@apiview.route('/samples/<int:sid>/comments/', methods=['GET'])
@login_required
def api_get_sample_comments(sid):
    """
        Get all the comments for a given sample
        @arg : address Get for one address
                default : get all the comments
        @arg : timestamp Limit the timeframe for comments
                (ie, how old you want the comments)
                default = 0, no limit
    """
    current_timestamp, addr = get_filter_arguments(request)
    data = api.idacontrol.get_comments(sid, addr, current_timestamp)
    return jsonify({'comments': data})


@apiview.route('/samples/<int:sid>/comments/', methods=['POST'])
@login_required
def api_post_sample_comments(sid):
    """
        Upload a new comment for a sample
    """
    if request.json is None:
        abort(400, "No JSON data")
    data = request.json
    if "address" not in data.keys() or "comment" not in data.keys():
        abort(400, "Missing comment or address arguments")
    address = data['address']
    comment = data['comment']
    user_id = current_user.id
    current_app.logger.debug(
        "Getting a new comment for sample %d : %s@0x%x",
        sid,
        comment,
        address)
    action_id = api.idacontrol.add_comment(address, comment, user_id)
    result = api.samplecontrol.add_idaaction(sid, action_id)
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/names/', methods=['GET'])
@login_required
def api_get_sample_names(sid):
    """
        Get names for a given sample
        @arg : addr Get for one address
                default : get all the names
        @arg : timestamp Limit the timeframe for names
                default = 0, no limit
    """
    current_timestamp, addr = get_filter_arguments(request)
    data = api.idacontrol.get_names(sid, addr, current_timestamp)
    return jsonify({'names': data})


@apiview.route('/samples/<int:sid>/names/', methods=['POST'])
@login_required
def api_post_sample_names(sid):
    """
        Upload a new names for a sample
        @arg addr the corresponding address
        @arg name the name
    """
    data = request.json
    addr = data['address']
    name = data['name']
    user_id = current_user.id
    current_app.logger.debug(
        "Getting a new name for sample %d : %s@0x%x",
        sid,
        name,
        addr)
    action_id = api.idacontrol.add_name(addr, name, user_id)
    result = api.samplecontrol.add_idaaction(sid, action_id)
    if result is True:
        api.samplecontrol.rename_func_from_action(sid, addr, name)
        # we don't care if the function is renamed for a global name,
        # so if the name is created return True anyway
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/types/', methods=['POST'])
@login_required
def api_post_sample_types(sid):
    """
        Manage the creation of type definitions at specific addresses
    """
    data = request.json
    addr = data['address']
    typedef = data['typedef']
    user_id = current_user.id

    action_id = api.idacontrol.add_typedef(addr, typedef, user_id)
    result = api.samplecontrol.add_idaaction(sid, action_id)
    return jsonify(dict(result=result))


@apiview.route('/samples/<int:sid>/types/', methods=['GET'])
@login_required
def api_get_sample_types(sid):
    """
        Get the IDA types stored in DB
    """
    current_timestamp, addr = get_filter_arguments(request)
    data = api.idacontrol.get_typedefs(sid, addr, current_timestamp)
    return jsonify({'typedefs': data})


@apiview.route('/samples/<int:sid>/structs/', methods=['POST'])
@login_required
def api_create_struct(sid):
    """
        Create a new IDA Struct for a given sample
        @arg name: the structure name
    """
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    result = False
    name = data['name']
    current_app.logger.debug("Creating structure %s" % name)
    user_id = current_user.id
    mstruct = api.idacontrol.create_struct(name=name, user_id=user_id)
    if mstruct is not False:
        result = api.samplecontrol.add_idaaction(sid, mstruct)
    return jsonify({'result': result, 'structs': [{'id': mstruct}]})


@apiview.route('/samples/<int:sid>/structs/', methods=['GET'])
@login_required
def api_get_sample_structs(sid):
    """
        Returns the structures associated with a sample
        @arg timestamp: get structs after this timestamp (optional)
    """
    timestamp = None
    if request.args is not None and 'timestamp' in request.args.keys():
        timestamp = request.args['timestamp']
    structs = api.idacontrol.get_structs(sid, timestamp)
    return jsonify({'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/', methods=['GET'])
@login_required
def api_get_one_struct(sid, struct_id):
    """
        Returns a unique struct
    """
    structs = api.idacontrol.get_one_struct(struct_id)
    return jsonify({'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['POST'])
@login_required
def api_create_struct_member(sid, struct_id):
    """
        Add a new member to a structure
    """
    result = False
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    name = data["name"]
    size = data["size"]
    offset = data["offset"]
    mid = api.idacontrol.create_struct_member(name=name,
                                              size=size,
                                              offset=offset)
    if mid is None:
        result = False
    else:
        result = api.idacontrol.add_member_to_struct(struct_id, mid)
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/structs/<string:struct_name>/')
@login_required
def api_get_struct_by_name(sid, struct_name):
    """
        Get structure data from a name
    """
    result = api.idacontrol.get_struct_by_name(sid, struct_name)
    return jsonify({'structs': result})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/',
               methods=["PATCH"])
@login_required
def api_rename_struct(sid, struct_id):
    """
        Rename a struct
    """
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    name = data["name"]
    result = api.idacontrol.rename_struct(struct_id, name)
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/',
               methods=["DELETE"])
@login_required
def api_delete_struct(sid, struct_id):
    """
        Completely delete a struct from database
    """
    result = api.idacontrol.delete_struct(struct_id)
    return jsonify({"result": result})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['PATCH'])
@login_required
def api_update_struct_member(sid, struct_id):
    """
        Modify a struct member
        Supported operations:
            - newname: change member name
            - newsize: resize the member
    """
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    mid = data["mid"]
    result = False
    if 'newname' in data.keys():
        result = api.idacontrol.change_struct_member_name(struct_id, mid,
                                                          data["newname"])
    if 'newsize' in data.keys():
        result = api.idacontrol.change_struct_member_size(struct_id, mid,
                                                          data["newsize"])
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['GET'])
@login_required
def api_get_struct_member(sid, struct_id):
    """
        Get all members of a struct
        TODO: implement and test
    """
    result = False
    structs = None
    return jsonify({'result': result, 'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['DELETE'])
@login_required
def api_delete_struct_member(sid, struct_id):
    """
        TODO : implement and test
    """
    result = False
    return jsonify({'result': result})
