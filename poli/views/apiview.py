"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Routes for REST API
"""

import os

from poli import api, apiview
from poli.models.family import FamilySchema
from poli.models.sample import Sample, SampleSchema

from flask import jsonify, request, redirect, send_file, abort, make_response


def plain_text(data):
    response = make_response(data)
    response.headers['Content-Type'] = 'text/plain'
    return response


@apiview.errorhandler(404)
def api_404_handler():
    return jsonify({'error': 404})

@apiview.errorhandler(500)
def api_404_handler():
    return jsonify({'error': 500})


@apiview.route('/api/')
@apiview.route('/')
def api_help():
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


"""
    Families
"""


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
    result = api.familycontrol.get_all_schema()
    return jsonify(result)


@apiview.route('/family/', methods=['POST'])
def api_post_families():
    """
        Insert a new family
        @return the created family id
    """
    data = request.json
    fname = data['name']
    if data['parent']:
        pfam = api.familycontrol.get_by_name(data['parent'])
        fam = api.familycontrol.create(fname, parentfamily=pfam)
    else:
        fam = api.familycontrol.create(fname)
    if fam is None:
        fid = 0
    else:
        fid = fam.id
    return jsonify({'family': fid})


@apiview.route('/family/<fname>', methods=['GET'])
def api_get_family(fname):
    fam = api.familycontrol.get_by_name(fname)
    if fam is None:
        return jsonify({"family": None})
    fschema = FamilySchema()
    data = fschema.dump(fam).data
    return jsonify({"family": data})


@apiview.route('/family/<fam_name>', methods=['POST'])
def api_post_family(fam_name):
    """
        TODO
    """
    abort(404)

"""
    Samples
"""


@apiview.route('/samples/<shash>/')
# TODO : API!!!
def api_get_sample_id_from_hash(shash):
    if len(shash) == 32:
        s = Sample.query.filter_by(md5=shash).first()
    elif len(shash) == 40:
        s = Sample.query.filter_by(sha1=shash).first()
    elif len(shash) == 64:
        s = Sample.query.filter_by(sha256=shash).first()
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
        return -1
    orig_filename = request.form['filename']
    sid = api.create_sample_and_run_analysis(mfile, orig_filename)
    if sid == -1:
        return redirect('404')

    result = api.samplecontrol.schema_export(sid)
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
    pass


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
    abstract = data['abstract']
    samp = api.samplecontrol.get_by_id(sid)
    result = api.samplecontrol.set_abstract(samp, abstract)
    return jsonify({'result': result})


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
    data = request.json
    data = api.idacontrol.get_comments(sid)
    return jsonify({'comments': data})


@apiview.route('/samples/<int:sid>/comments/', methods=['POST'])
def api_post_sample_comments(sid):
    """
        Upload a new comment for a sample
    """
    if request.json is None:
        abort(500)
    data = request.json
    if "address" not in data.keys():
        abort(500)
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
    data = request.json
    current_timestamp, addr = None, None
    if data is not None:
        if 'timestamp' in data.keys():
            current_timestamp = data['timestamp']
        if 'addr' in data.keys():
            addr = data['addr']
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
        result = api.samplecontrol.rename_func_from_action(sid, addr, name)
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
        TODO : Get yara hashes
    """
    samp = api.samplecontrol.get_by_id(sid)
    result = None
    return jsonify({'result': result})
