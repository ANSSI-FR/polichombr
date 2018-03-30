"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        API endpoints managing families
"""

import os

from polichombr import api
from polichombr.views.apiview import apiview
from polichombr.models.family import FamilySchema
from polichombr.models.models import TLPLevel

from flask_security import login_required

from flask import jsonify, request, send_file, abort, make_response
from flask import current_app


def plain_text(data):
    """
        Return as plaintext data,
        useful for IOCs, Yaras, abstracts...
    """
    response = make_response(data)
    response.headers['Content-Type'] = 'text/plain'
    return response


@apiview.route(
    '/family/<family_id>/export/<int:tlp_level>/detection/yara',
    methods=['GET'])
@login_required
def api_family_export_detection_yara(family_id, tlp_level):
    """
        This endpoint is ugly, should replace with tlp in argument
    """
    my_family = api.get_elem_by_type("family", family_id)
    return plain_text(
        api.familycontrol.export_yara_ruleset(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/snort',
    methods=['GET'])
@login_required
def api_family_export_detection_snort(family_id, tlp_level):
    my_family = api.get_elem_by_type("family", family_id)
    return plain_text(
        api.familycontrol.export_detection_snort(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/openioc/',
    methods=['GET'])
@login_required
def api_family_export_detection_openioc(family_id, tlp_level):
    """
        This endpoint format should be reimplemented
    """
    my_family = api.get_elem_by_type("family", family_id)
    return plain_text(
        api.familycontrol.export_detection_openioc(my_family, tlp_level))


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/detection/custom_elements',
    methods=['GET'])
@login_required
def api_family_export_detection_custom_elements(family_id, tlp_level):
    my_family = api.get_elem_by_type("family", family_id)
    return plain_text(
        api.familycontrol.export_detection_custom(my_family, tlp_level))


@apiview.route(
    '/family/<int:family_id>/export/<int:tlp_level>/samplesarchive/',
    methods=['GET'])
@login_required
def api_family_export_sampleszip(family_id, tlp_level):
    my_family = api.get_elem_by_type("family", family_id)
    zpath = api.familycontrol.generate_samples_zip_file(my_family, tlp_level)
    if zpath is None:
        return ""
    return send_file("../" + zpath, as_attachment=True,
                     attachment_filename="export.tar.gz")


@apiview.route(
    '/family/<family_id>/export/<tlp_level>/samplesioc/',
    methods=['GET'])
@login_required
def api_family_export_samplesioc(family_id, tlp_level):
    my_family = api.get_elem_by_type("family", family_id)
    return plain_text(
        api.familycontrol.export_samplesioc(my_family, tlp_level))


@apiview.route('/families/', methods=['GET'])
@login_required
@login_required
def api_get_families():
    """
        Exports all the families
    """
    result = api.familycontrol.get_all_schema()
    return jsonify(result)


@apiview.route('/family/', methods=['POST'])
@login_required
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
        if tlp_level is None:
            tlp_level = TLPLevel.TLPAMBER

    except KeyError:
        current_app.logger.warning("No TLP for family, default to AMBER")

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
@login_required
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
@login_required
def api_get_family_by_id(fid):
    """
        Get family informations
    """
    fam = api.get_elem_by_type("family", fid)
    schema = FamilySchema()
    result = schema.dump(fam).data
    return jsonify({"family": result})


@apiview.route('/family/<int:fid>/abstract/', methods=['POST'])
@login_required
def api_set_family_abstract(fid):
    """
        @arg abstract: The family abstract
    """
    if request.json is None:
        abort(400, "Missing JSON data")

    try:
        family = api.get_elem_by_type("family", fid)
        abstract = request.json["abstract"]
        result = api.familycontrol.set_abstract(family, abstract)
        return jsonify({"result": result})

    except KeyError:
        abort(400, "Missing abstract data")


@apiview.route('/family/<int:fid>/yaras/', methods=['POST'])
@login_required
def api_add_yara_to_family(fid):
    """
        Add a yara rule to a family
    """
    family = api.get_elem_by_type("family", fid)
    try:
        rule_name = request.json["rule_name"]
        rule = api.yaracontrol.get_by_name(rule_name)
        if rule is None:
            raise KeyError
        result = api.yaracontrol.add_to_family(family, rule)
    except KeyError:
        abort(400, "Unknown yara")
    return jsonify({"result": result})


@apiview.route('/family/<fam_name>', methods=['POST'])
@login_required
def api_post_family(fam_name):
    """
        TODO: Update a family from POST request
    """
    abort(404)


@apiview.route('/family/<int:family_id>/attachment/<int:file_id>/')
@login_required
def download_family_file(family_id, file_id):
    """
    Family attachment download endpoint.
    """
    attachment = api.get_elem_by_type("family_file", file_id)
    data_file = attachment.filepath
    if not os.path.exists(data_file):
        abort(404)
    return send_file('../' + data_file,
                     as_attachment=True,
                     attachment_filename=os.path.basename(data_file))
