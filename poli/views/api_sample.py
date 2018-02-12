"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        API endpoints related to the samples
"""
import os

from poli import api
from poli.views.apiview import apiview
from poli.models.sample import Sample, SampleSchema
from poli.models.models import TLPLevel
from poli.models.sample import FunctionInfoSchema

from flask import jsonify, request, send_file, abort, current_app
from flask_security import login_required


@apiview.route('/samples/<shash>/')
@login_required
def api_get_sample_id_from_hash(shash):
    """
        Useful for initialization of scripts, get the remote
        sample ID when you known only the sample hash
    """
    if len(shash) == 32:
        sample = Sample.query.filter_by(md5=shash).first()
    elif len(shash) == 40:
        sample = Sample.query.filter_by(sha1=shash).first()
    elif len(shash) == 64:
        sample = Sample.query.filter_by(sha256=shash).first()
    else:
        abort(400, "Invalid hash length")
    if sample is not None:
        return jsonify({'sample_id': sample.id})
    return jsonify({'sample_id': None})


@apiview.route('/samples/<int:sid>/download/')
@login_required
def api_get_sample_file(sid):
    """
        Return the sample binary
    """
    sample = api.get_elem_by_type("sample", sid)
    data_file = sample.storage_file
    return send_file('../' + data_file,
                     as_attachment=True,
                     attachment_filename=os.path.basename(data_file))


@apiview.route('/samples/', methods=['GET'])
@login_required
def api_get_samples():
    """
        Returns all the samples
    """
    result = api.samplecontrol.schema_export_all()
    data = jsonify({'samples': result})
    return data


@apiview.route('/samples/', methods=['POST'])
@login_required
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
        current_app.logger.debug("Could not find the tlp_level key")

    try:
        orig_filename = request.form['filename']
    except KeyError:
        current_app.logger.debug("No filename provided")
        orig_filename = ""

    samples = api.dispatch_sample_creation(mfile, orig_filename)
    if len(samples) == 0:
        abort(500, "Cannot create sample")

    if tlp_level not in range(1, 6):
        current_app.logger.warning("Incorrect TLP level, defaulting to AMBER")
        tlp_level = TLPLevel.TLPAMBER

    for sample in samples:
        result = api.samplecontrol.set_tlp_level(sample, tlp_level)
        if result is False:
            current_app.logger.warning(
                "Cannot set TLP level for sample %d" % sample.id)
    result = api.samplecontrol.schema_export_many(samples)

    return jsonify({'sample': result})


@apiview.route('/samples/<int:sid>/', methods=['GET'])
@login_required
def api_get_unique_sample(sid):
    sample_schema = SampleSchema()
    data = Sample.query.get(sid)
    if data is None:
        return '{}'
    result = sample_schema.dump(data).data
    data = jsonify({'samples': result})
    return data


@apiview.route('/samples/<int:sid>/', methods=['POST'])
@login_required
def api_post_unique_sample(sid):
    abort(405)


@apiview.route('/samples/<int:sid>/analysis/', methods=['GET'])
@login_required
def api_get_sample_full_analysis(sid):
    return jsonify({'analysis': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/analyzeit/', methods=['GET'])
@login_required
def api_get_sample_analyzeit(sid):
    return jsonify({'analyzeit': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/strings/', methods=['GET'])
@login_required
def api_get_sample_strings(sid):
    return jsonify({'strings': 'Not implemented'})


@apiview.route('/samples/<int:sid>/analysis/peinfo/', methods=['GET'])
@login_required
def api_get_sample_peinfo(sid):
    return jsonify({'peinfo': 'not implemented'})


@apiview.route('/samples/<int:sid>/families/', methods=['POST'])
@login_required
def api_post_sample_family(sid):
    samp = api.get_elem_by_type("sample", sid)
    if request.json is None:
        abort(400, "JSON not provided")
    fam = None
    if "family_id" in request.json.keys():
        fid = request.json['family_id']
        fam = api.get_elem_by_type("family", fid)
    elif "family_name" in request.json.keys():
        fname = request.json['family_name']
        fam = api.familycontrol.get_by_name(fname)
    else:
        return jsonify({'result': False})
    result = api.familycontrol.add_sample(samp, fam)

    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/abstract/', methods=['POST'])
@login_required
def api_set_sample_abstract(sid):
    """
        @arg: abstract Markdown for the abstract
    """
    data = request.json
    if data is None or 'abstract' not in data.keys():
        abort(400, 'Invalid JSON data provided')
    abstract = data['abstract']
    samp = api.get_elem_by_type("sample", sid)
    result = api.samplecontrol.set_abstract(samp, abstract)
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/abstract/', methods=['GET'])
@login_required
def api_get_sample_abstract(sid):
    """
        Returns the raw markdown sample abstract
    """
    sample = api.get_elem_by_type("sample", sid)
    result = sample.abstract
    return jsonify({'abstract': result})


@apiview.route('/samples/<int:sid>/matches/', methods=['GET'])
@login_required
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
@login_required
def api_get_machoc_matches(sid):
    """
        TODO : Get machoc hashes
    """
    sample = api.get_elem_by_type("sample", sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/iat_hash', methods=['GET'])
@login_required
def api_get_iat_matches(sid):
    """
        TODO : Get IAT hashes
    """
    sample = api.get_elem_by_type("sample", sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/samples/<int:sid>/matches/yara', methods=['GET'])
@login_required
def api_get_yara_matches(sid):
    """
        TODO : Get yara matches
    """
    sample = api.get_elem_by_type("sample", sid)
    result = None
    return jsonify({'result': result})


@apiview.route('/machoc/<int:machoc_hash>', methods=["GET"])
@login_required
def api_get_machoc_names(machoc_hash):
    """
        Get user-defined names associated with machoc hashes
        @arg machoc_hash
        @return A list of names
    """
    functions = api.samplecontrol.get_functions_by_machoc_hash(machoc_hash)
    current_app.logger.debug("Got %d functions matching machoc %x",
                             len(functions),
                             machoc_hash)

    schema = FunctionInfoSchema(many=True)
    return jsonify(schema.dump(functions).data)
