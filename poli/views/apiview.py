"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Routes for REST API
"""

import os

from poli import api, apiview, app
from poli.models.family import FamilySchema
from poli.models.sample import Sample, SampleSchema
from poli.models.yara_rule import YaraSchema
from poli.models.models import TLPLevel

from flask import jsonify, request, send_file, abort, make_response


def plain_text(data):
    response = make_response(data)
    response.headers['Content-Type'] = 'text/plain'
    return response

@apiview.errorhandler(404)
def api_404_handler(error):
    return jsonify(dict(error=404, error_description="Resource not found")), 404

@apiview.errorhandler(500)
def api_500_handler(error):
    return jsonify({'error': 500,
                    'error_description': error.description,
                    'error_message': error.message}), 500


@apiview.errorhandler(400)
def api_400_handler(error):
    return jsonify({'error': 400,
                    'error_description': error.description,
                    'error_message': error.message}), 400

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
    /
    /samples/
    /samples/
    /samples/<int:sid>/download
    /samples/<int:sid>
    /samples/<shash>/

    /families/
        Get all the data for all the families

    /family/
        [POST] : create a new family
        [GET]  : nothing
    """
    return plain_text(text)


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/yara',
    methods=['GET'])
def api_family_export_detection_yara(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    return plain_text(
        api.familycontrol.export_yara_ruleset(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/snort',
    methods=['GET'])
def api_family_export_detection_snort(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    return plain_text(
        api.familycontrol.export_detection_snort(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/openioc',
    methods=['GET'])
def api_family_export_detection_openioc(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    return plain_text(
        api.familycontrol.export_detection_openioc(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/custom_elements',
    methods=['GET'])
def api_family_export_detection_custom_elements(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    return plain_text(
        api.familycontrol.export_detection_custom(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/samplesarchive',
    methods=['GET'])
def api_family_export_sampleszip(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    zpath = api.familycontrol.generate_samples_zip_file(my_family, tlp_level)
    if zpath is None:
        return ""
    return send_file("../" + zpath, as_attachment=True,
                     attachment_filename="export.tar.gz")


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/samplesioc',
    methods=['GET'])
def api_family_export_samplesioc(family_id, tlp_level):
    my_family = api.familycontrol.get_by_id(family_id)
    if my_family is None:
        abort(404)
    return plain_text(
        api.familycontrol.export_samplesioc(my_family, tlp_level))


@apiview.route('/families/', methods=['GET'])
def api_get_families():
    """
        Exports all the families
    """
    result = api.familycontrol.get_all_schema()
    return jsonify(result)


@apiview.route('/family/', methods=['POST'])
def api_post_families():
    """
        Insert a new family
        @return the created family id
    """
    data = request.json
    if data is None:
        abort(400, "Missing JSON arguments")
    fname = data['name']
    tlp_level = TLPLevel.TLPAMBER
    try:
        tlp_level = data['tlp_level']
    except KeyError:
        app.logger.warning("No TLP for family, default to AMBER")

    pfam = None
    try:
        if data['parent']:
            pfam = api.familycontrol.get_by_name(data['parent'])
    except KeyError:
        pass

    fam = api.familycontrol.create(fname, parentfamily=pfam)
    if fam is None:
        fid = None
    else:
        api.familycontrol.set_tlp_level(fam, tlp_level, no_propagation=True)
        fid = fam.id
    return jsonify({'family': fid})


@apiview.route('/family/<fname>/', methods=['GET'])
def api_get_family(fname):
    """
        Get family data using it's name
    """
    fam = api.familycontrol.get_by_name(fname)
    if fam is None:
        return jsonify({"family": None})
    fschema = FamilySchema()
    data = fschema.dump(fam).data
    return jsonify({"family": data})


@apiview.route('/family/<int:fid>/', methods=['GET'])
def api_get_family_by_id(fid):
    fam = api.familycontrol.get_by_id(fid)
    if fam is None:
        result = None
    else:
        schema = FamilySchema()
        result = schema.dump(fam).data
    return jsonify({"family": result})

@apiview.route('/family/<int:fid>/abstract/', methods=['POST'])
def api_set_family_abstract(fid):
    """
        @arg abstract: The family abstract
    """
    if request.json is None:
        abort(400, "Missing JSON data")

    try:
        family = api.familycontrol.get_by_id(fid)
        abstract = request.json["abstract"]
        result = api.familycontrol.set_abstract(family, abstract)
        return jsonify({"result": result})

    except KeyError:
        abort(400, "Missing abstract data")

@apiview.route('/family/<fam_name>', methods=['POST'])
def api_post_family(fam_name):
    """
        TODO
    """
    abort(404)


@apiview.route('/samples/<shash>/')
def api_get_sample_id_from_hash(shash):
    if len(shash) == 32:
        s = Sample.query.filter_by(md5=shash).first()
    elif len(shash) == 40:
        s = Sample.query.filter_by(sha1=shash).first()
    elif len(shash) == 64:
        s = Sample.query.filter_by(sha256=shash).first()
    else:
        abort(400, "Invalid hash length")
    if s is not None:
        return jsonify({'sample_id': s.id})
    return jsonify({'sample_id': None})


@apiview.route('/samples/<int:sid>/download/')
def api_get_sample_file(sid):
    s = api.samplecontrol.get_by_id(sid)
    if s is None:
        abort(404)
    fp = s.storage_file
    return send_file('../' + fp,
                     as_attachment=True,
                     attachment_filename=os.path.basename(fp))


@apiview.route('/samples/', methods=['GET'])
def api_get_samples():
    result = api.samplecontrol.schema_export_all()
    data = jsonify({'samples': result})
    return data


@apiview.route('/samples/', methods=['POST'])
def api_post_samples():
    """
    @description : Insert a new sample in database, launch analysis
    @arg: string filename
    @arg: binary data : the sample content
    @return : the sample ID
    """

    mfile = request.files['file']
    if not mfile:
        abort(400, "You must provide a file object")

    tlp_level = TLPLevel.TLPAMBER
    try:
        tlp_level = int(request.form["tlp_level"])
    except KeyError:
        app.logger.debug("Could not find the tlp_level key")

    orig_filename = request.form['filename']
    msample = api.create_sample_and_run_analysis(mfile, orig_filename)
    if msample is None:
        abort(500, "Cannot create sample")

    if tlp_level not in range(1, 6):
        app.logger.warning("Incorrect TLP level, defaulting to AMBER")
        tlp_level = TLPLevel.TLPAMBER

    result = api.samplecontrol.set_tlp_level(msample, tlp_level)
    if result is False:
        app.logger.warning("Cannot set TLP level for sample %d " % msample.id)

    result = api.samplecontrol.schema_export(msample)

    return jsonify({'sample': result})


@apiview.route('/samples/<int:sid>/', methods=['GET'])
def api_get_unique_sample(sid):
    sample_schema = SampleSchema()
    data = Sample.query.get(sid)
    if data is None:
        return '{}'
    result = sample_schema.dump(data).data
    data = jsonify({'samples': result})
    return data


@apiview.route('/samples/<int:sid>/', methods=['POST'])
def api_post_unique_sample(sid):
    abort(405)


@apiview.route('/samples/<int:sid>/analysis/', methods=['GET'])
def api_get_sample_full_analysis(sid):
    return jsonify({'analysis': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/analyzeit/', methods=['GET'])
def api_get_sample_analyzeit(sid):
    return jsonify({'analyzeit': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/strings/', methods=['GET'])
def api_get_sample_strings(sid):
    return jsonify({'strings': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/peinfo/', methods=['GET'])
def api_get_sample_peinfo(sid):
    return jsonify({'peinfo': 'not implemented'})


@apiview.route('/samples/<int:sid>/families/', methods=['POST'])
def api_post_sample_family(sid):
    samp = api.samplecontrol.get_by_id(sid)
    if samp is None:
        return jsonify({'result': False})
    fam = None
    if "family_id" in request.json.keys():
        fid = request.json['family_id']
        fam = api.familycontrol.get_by_id(fid)
    elif "family_name" in request.json.keys():
        fname = request.json['family_name']
        fam = api.familycontrol.get_by_name(fname)
    else:
        return jsonify({'result': False})
    result = api.familycontrol.add_sample(samp, fam)

    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/abstract/', methods=['POST'])
def api_set_sample_abstract(sid):
    """
        @arg: abstract Markdown for the abstract
    """
    data = request.json
    if data is None or 'abstract' not in data.keys():
        abort(400, 'Invalid JSON data provided')
    abstract = data['abstract']
    samp = api.samplecontrol.get_by_id(sid)
    result = api.samplecontrol.set_abstract(samp, abstract)
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/abstract/', methods=['GET'])
def api_get_sample_abstract(sid):
    """
        Returns the raw markdown sample abstract
    """
    sample = api.samplecontrol.get_by_id(sid)
    if sample is None:
        abort(404)
    result = sample.abstract
    return jsonify({'abstract': result})


def get_filter_arguments(mrequest):
    """
        Get timestamp and address from request
    """
    data = mrequest.args
    current_timestamp, addr = None, None
    if data is not None:
        if 'timestamp' in data.keys():
            current_timestamp = data['timestamp']
        if 'addr' in data.keys():
            addr = int(data['addr'], 16)
    return current_timestamp, addr



@apiview.route('/samples/<int:sid>/comments/', methods=['GET'])
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
    action_id = api.idacontrol.add_comment(address, comment)
    result = api.samplecontrol.add_idaaction(sid, action_id)
    return jsonify({'result': result})



@apiview.route('/samples/<int:sid>/names/', methods=['GET'])
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
def api_post_sample_names(sid):
    """
        Upload a new names for a sample
        @arg addr the corresponding address
        @arg name the name
    """

    data = request.json
    addr = data['address']
    name = data['name']
    action_id = api.idacontrol.add_name(addr, name)
    result = api.samplecontrol.add_idaaction(sid, action_id)
    if result is True:
        api.samplecontrol.rename_func_from_action(sid, addr, name)
        # we don't care if the function is renamed for a global name,
        # so if the name is created return True anyway
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/structs/', methods=['POST'])
def api_create_struct(sid):
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    result = False
    name = data['name']
    app.logger.debug("Creating structure %s" % name)
    mstruct = api.idacontrol.create_struct(name=name)
    if mstruct is not False:
        result = api.samplecontrol.add_idaaction(sid, mstruct)
    return jsonify({'result': result, 'structs': [{'id': mstruct}]})


@apiview.route('/samples/<int:sid>/structs/', methods=['GET'])
def api_get_sample_structs(sid):
    timestamp = None
    if request.args is not None and 'timestamp' in request.args.keys():
        timestamp = request.args['timestamp']
    structs = api.idacontrol.get_structs(sid, timestamp)
    return jsonify({'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/', methods=['GET'])
def api_get_one_structs(sid, struct_id):
    structs = api.idacontrol.get_one_struct(struct_id)

    return jsonify({'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['POST'])
def api_create_struct_member(sid, struct_id):
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


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['PATCH'])
def api_update_struct_member(sid, struct_id):
    data = request.json
    if data is None:
        abort(400, "Missing JSON data")
    mid = data["mid"]
    result = False
    if 'newname' in data.keys():
        result = api.idacontrol.change_struct_member_name(sid, mid,
                                                          data["newname"])
    if 'newsize' in data.keys():
        result = api.idacontrol.change_struct_member_size(sid, mid,
                                                          data["newsize"])
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['GET'])
def api_get_struct_member(sid, struct_id):
    result = False
    structs = None
    return jsonify({'result': result, 'structs': structs})


@apiview.route('/samples/<int:sid>/structs/<int:struct_id>/members/',
               methods=['DELETE'])
def api_delete_struct_member(sid, struct_id):
    """
        TODO : implement and test
    """
    result = False
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/', methods=['GET'])
def api_get_matches(sid):
    """
    TODO
        Get all the matches :
            - Yara
            - IAT hash
            - Machoc
    """
    result = None
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/machoc', methods=['GET'])
def api_get_machoc_matches(sid):
    """
        TODO : Get machoc hashes
    """
    samp = api.samplecontrol.get_by_id(sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/iat_hash', methods=['GET'])
def api_get_iat_matches(sid):
    """
        TODO : Get IAT hashes
    """
    samp = api.samplecontrol.get_by_id(sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/yara', methods=['GET'])
def api_get_yara_matches(sid):
    """
        TODO : Get yara matches
    """
    samp = api.samplecontrol.get_by_id(sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/yaras/', methods=['GET'])
def api_get_all_yaras():
    """
        Dump all the yaras
    """
    yaras = api.yaracontrol.get_all()
    schema = YaraSchema(many=True)
    return jsonify({'yara_rules': schema.dump(yaras).data})

@apiview.route('/yaras/', methods=['POST'])
def api_create_yara():
    """
        Add a new yara
        @arg name: the yara name
        @arg rule: the full text of the rule
        @arg tlp_level: Optional, the sensibility of the rule. Default = TLP AMBER
    """
    tlp_level = None
    data = request.json
    name = data["name"]
    rule = data["rule"]
    if 'tlp_level' in data.keys():
        tlp_level = data["tlp_level"]

    if tlp_level is None:
        tlp_level = TLPLevel.TLPAMBER

    result = api.yaracontrol.create(name, rule, tlp_level)
    if result is None or not result:
        abort(500, "Cannot create yara rule")
    return jsonify({"id": result.id})
