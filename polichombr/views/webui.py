"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Routes and forms parsing for the main web interface.
"""


import json
import io
import glob

from zipfile import ZipFile

from flask import render_template, g, redirect, url_for, flash, Blueprint
from flask import current_app
from flask import abort, make_response, request
from flask_security import current_user
from flask_security import login_required

from polichombr import api

from polichombr.models.family import Family
from polichombr.models.sample import Sample, SampleMetadataType

from polichombr.views.forms import YaraForm, ChangeTLPForm
from polichombr.views.forms import RenameForm
from polichombr.views.forms import FullTextSearchForm, HashSearchForm
from polichombr.views.forms import CreateCheckListForm, MachocHashSearchForm
from polichombr.views.forms import UploadSampleForm


webuiview = Blueprint('webuiview', __name__, static_folder="static")

# Import the subview
from .webui_families import *
from .webui_user import *
from .webui_sample import *


@webuiview.errorhandler(404)
def not_found(error):
    """
        404 management
    """
    current_app.logger.error(error)
    return render_template('error.html', error=error), 404


@webuiview.errorhandler(401)
def api_401_handler(error):
    """
        module wide error handler, returned when there is an argument problem
    """
    current_app.logger.error(error)
    return render_template('error.html', error=error), 401


@webuiview.before_request
def before_request():
    """
        Affects global variables for each request
    """
    g.user = current_user
    # Query the last 15 samples for displaying in the index page
    g.samples = Sample.query.order_by(Sample.id.desc()).limit(15).all()


@webuiview.route('/')
@webuiview.route('/index/')
def index():
    """
    Index. Distinction between logged-in users and guests is performed
    in the template.
    """
    upload_sample_form = UploadSampleForm()
    families_choices = [(0, "None")]
    families_choices += [(f.id, f.name) for f in Family.query.order_by('name')]
    upload_sample_form.family.choices = families_choices
    uncategorized = []
    if g.user.is_authenticated:
        uncategorized = api.samplecontrol.get_user_uncategorized_samples(
            g.user)
    return render_template('index.html',
                           families=api.familycontrol.get_all(),
                           uncategorized=uncategorized,
                           form=upload_sample_form)


@webuiview.route('/skelenox/', methods=['GET', 'POST'])
@login_required
def dl_skelenox():
    """
        Generate a Zip file wich contains both the Skelenox script
        and the associated config file.
    """
    try:
        ip_addr, _ = request.host.split(":")
    except ValueError:
        ip_addr = request.host

    zipout = io.BytesIO()
    with ZipFile(zipout, "w") as myzip:
        myzip.write("skelenox.py")
        myzip.write("skelenox_plugin")
        for module in glob.glob("skelenox_plugin/*.py"):
            myzip.write(module)
        skel_config = {}
        skel_config["edit_flag"] = True
        skel_config["initial_sync"] = True
        skel_config["poli_server"] = ip_addr
        skel_config["poli_port"] = current_app.config['SERVER_PORT']
        skel_config["poli_remote_path"] = current_app.config['API_PATH'] + "/"
        skel_config["debug_http"] = current_app.config['HTTP_DEBUG']
        skel_config["poli_apikey"] = g.user.api_key
        skel_config["save_timeout"] = 10 * 60
        skel_config["sync_frequency"] = 1 * 100
        skel_config["debug_level"] = "info"
        skel_config["notepad_font_name"] = "Courier New"
        skel_config["notepad_font_size"] = 9
        skel_config["use_ui"] = True
        skel_json = json.dumps(skel_config, sort_keys=True, indent=4)
        myzip.writestr("skelsettings.json", skel_json)
        myzip.close()
    response = make_response(zipout.getvalue())
    response.headers["Content-type"] = "application/octet-stream"
    response.headers[
        "Content-Disposition"] = "attachment; filename=skelenox.zip"
    return response


@webuiview.route('/settings/', methods=['GET', 'POST'])
@login_required
def ui_settings():
    """
        Manage application settings (checklist for the moment)
    """
    addchecklistform = CreateCheckListForm()
    if addchecklistform.validate_on_submit():
        api.samplecontrol.create_checklist(addchecklistform.title.data,
                                           addchecklistform.description.data)
    return render_template("settings.html",
                           addchecklistform=addchecklistform,
                           checklists=api.samplecontrol.get_all_checklists(),
                           users=api.usercontrol.get_all())


@webuiview.route('/settings/deletechecklist/<int:checklist_id>/',
                 methods=['GET'])
@login_required
def deletechecklist(checklist_id):
    """
    Delete a checklist element.
    """
    checklist_item = api.samplecontrol.get_checklist_by_id(checklist_id)
    if not checklist_item:
        abort(404)
    current_app.logger.debug("deleting checklist %s", checklist_item.title)
    api.samplecontrol.delete_checklist(checklist_item)
    return redirect(url_for('webuiview.ui_settings'))


@webuiview.context_processor
def utility_processor():
    """
        define utilities for Jinja processing
    """
    def format_metadata(meta):
        """
            Used to format correctly a sample metadata type in Jinja
        """
        return '%s' % (SampleMetadataType.tostring(meta.type_id))
    return dict(format_meta=format_metadata)


@webuiview.route('/search/', methods=['GET', 'POST'])
@login_required
def ui_search():
    """
    Handle search forms
    """
    hform = HashSearchForm()
    tform = FullTextSearchForm()
    mhform = MachocHashSearchForm()

    hash_compare_results = None
    samples_results = None
    functions_results = None
    if hform.validate_on_submit():
        hneedle = hform.hneedle.data
        samples_results, functions_results = api.samplecontrol.search_hash(
            hneedle)
        if not samples_results:
            flash("Hash not found...", "error")
    if tform.validate_on_submit():
        tneedle = tform.fneedle.data
        samples_results = api.samplecontrol.search_fulltext(tneedle)
    if mhform.validate_on_submit():
        comparison_level = mhform.percent.data
        if comparison_level > 100:
            comparison_level = 100
        elif comparison_level < 1:
            comparison_level = 1
        comparison_level = float(comparison_level) / 100
        needle = mhform.mneedle.data
        hash_compare_results = api.samplecontrol.search_machoc_full_hash(
            needle, comparison_level)

    return render_template('search.html',
                           hform=hform,
                           tform=tform,
                           mhform=mhform,
                           mresults=functions_results,
                           hresults=hash_compare_results,
                           results=samples_results)


@webuiview.route('/signatures/', methods=['GET', 'POST'])
@login_required
def ui_yara():
    """
    Yara signatures view.
    """
    create_yara_form = YaraForm()
    change_tlp_level_form = ChangeTLPForm()
    rename_yara_form = RenameForm()

    if create_yara_form.validate_on_submit():
        ret = api.yaracontrol.create(
            create_yara_form.yara_name.data,
            create_yara_form.yara_raw.data,
            create_yara_form.yara_tlp.data)
        if not ret:
            flash("Error during yara creation", "error")
        else:
            flash("Created yara " + ret.name, "success")
    elif change_tlp_level_form.validate_on_submit():
        if change_tlp_level_form.item_id:
            yar = api.get_elem_by_type("yara",
                                       change_tlp_level_form.item_id.data)
            api.yaracontrol.set_tlp_level(
                change_tlp_level_form.level.data, yar)
    elif rename_yara_form.validate_on_submit():
        if rename_yara_form.item_id:
            yar = api.get_elem_by_type("yara",
                                       rename_yara_form.item_id.data)
            api.yaracontrol.rename(rename_yara_form.newname.data, yar)

    yaras = api.yaracontrol.get_all()
    return render_template("signatures.html",
                           myyaras=yaras,
                           changetlpform=change_tlp_level_form,
                           renameform=rename_yara_form,
                           yaraform=create_yara_form)


@webuiview.route('/signatures/delete/<int:sig_id>')
@login_required
def ui_delete_yara(sig_id):
    """
    Delete YARA rule.
    """
    yar = api.get_elem_by_type("yara", sig_id)
    name = yar.name
    api.yaracontrol.delete(yar)
    flash("Deleted rule " + name, "success")
    return redirect(url_for('webuiview.ui_yara'))
