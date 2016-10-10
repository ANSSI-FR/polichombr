"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Routes and forms parsing for the main web interface.
"""


import json
import os
import io

from flask import render_template, g, redirect, url_for, flash
from flask import abort, make_response, request, jsonify
from flask_security import login_user, logout_user, current_user
from flask_security import login_required, roles_required
from werkzeug import secure_filename
from zipfile import ZipFile

from poli import app, api

from poli.models.family import Family
from poli.models.user   import User
from poli.models.sample import Sample, SampleMetadataType
from poli.models.yara_rule import YaraRule

from poli.views.forms import LoginForm, UserRegistrationForm
from poli.views.forms import ChgNameForm, ChgThemeForm
from poli.views.forms import SampleAbstractForm, UploadSampleForm, ChgPassForm
from poli.views.forms import FamilyForm, AddSampleToFamilyForm
from poli.views.forms import FamilyAbstractForm, AddYaraToFamilyForm
from poli.views.forms import AddSubFamilyForm, UploadFamilyFileForm
from poli.views.forms import ChangeTLPForm, ChangeStatusForm, ChgNickForm
from poli.views.forms import YaraForm, ExportMachexForm
from poli.views.forms import ExportFamilyForm, ImportForm, RenameForm
from poli.views.forms import FullTextSearchForm, HashSearchForm
from poli.views.forms import CreateCheckListForm, MachocHashSearchForm
from poli.views.forms import CompareMachocForm, CreateDetectionItemForm

from poli.controllers.sample import disassemble_sample_get_svg

"""

    GENERIC, PREPROCESSING, ERROR LANDINGS

"""


@app.errorhandler(404)
def not_found(error):
    """
        404 management
    """
    app.logger.error(error)
    return render_template('error.html'), 404


@app.before_request
def before_request():
    """
        Affects global variables for each request
    """
    g.user = current_user
    g.families = Family.query.all()
    g.samples = Sample.query.all()


"""

    INDEX, LOGIN AND REGISTRATION

"""


@app.route('/')
@app.route('/index/')
def index():
    """
    Index. Distinction between logged-in users and guests is performed
    in the template.
    """
    machex_import_form = ImportForm()
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
                           impform=machex_import_form,
                           uncategorized=uncategorized,
                           form=upload_sample_form)


@app.route('/login/', methods=['GET', 'POST'])
#@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Flask-Login.
    """
    if g.user.is_authenticated:
        return redirect(url_for('index'))

    login_form = LoginForm()
    if login_form.validate_on_submit():
        username = login_form.username.data
        user = api.usercontrol.get_by_name(username)
        if user is None:
            return redirect(url_for('login'))
        if api.usercontrol.check_user_pass(user, login_form.password.data):
            login_user(user, remember=True)
            flash("Logged in!", "success")
            return redirect(url_for("index"))
        else:
            flash("Cannot login...", "error")
    return render_template('login.html', title='Sign In', form=login_form)


@app.route('/register/', methods=['GET', 'POST'])
def register_user():
    """
    User registration, if enabled in configuration file.
    """
    if g.user.is_authenticated or app.config['USERS_CAN_REGISTER'] is not True:
        return redirect(url_for('index'))
    registration_form = UserRegistrationForm()
    if registration_form.validate_on_submit():
        ret = api.usercontrol.create(registration_form.username.data,
                               registration_form.password.data,
                               registration_form.completename.data,
                               )
        if ret:
            return redirect(url_for('login'))
        else:
            app.logger.error("Error during user registration")
            flash("Error registering user")
    return render_template('register.html',
                           form=registration_form)


@app.route('/logout/')
@login_required
def logout():
    """
    Logout.
    """
    logout_user()
    return redirect(url_for('index'))


"""

    SETTINGS AND MANAGEMENT

"""


@app.route('/skelenox/', methods=['GET', 'POST'])
@login_required
def dl_skelenox():
    ipaddr, port = request.host.split(":")
    zipout = io.BytesIO()
    with ZipFile(zipout, "w") as myzip:
        myzip.write("skelenox.py")
        gsx = {}
        gsx["username"] = g.user.nickname
        gsx["edit_flag"] = True
        gsx["poli_server"] = ipaddr
        gsx["poli_port"] = port
        gsx["poli_remote_path"] = "/"
        gsx["debug_http"] = False
        gsx["poli_apikey"] = g.user.api_key
        gsx["online_at_startup"] = False
        gsx["poli_timeout"] = 5
        gsx["display_subs_info"] = False
        gsx["int_func_lines_count"] = 9
        gsx["save_timeout"] = 10 * 60
        gsx["auto_highlight"] = 1
        gsx["backgnd_highlight_color"] = 0xA0A0FF
        gsx["backgnd_std_color"] = 0xFFFFFFFF
        gsx["notepad_font_name"] = "Courier New"
        gsx["notepad_font_size"] = 9
        sx = json.dumps(gsx, sort_keys=True, indent=4)
        myzip.writestr("skelsettings.json", sx)
        myzip.close()
    response = make_response(zipout.getvalue())
    response.headers["Content-type"] = "application/octet-stream"
    response.headers[
        "Content-Disposition"] = "attachment; filename=skelenox.zip"
    return response


@app.route('/admin/', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_page():
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route('/settings/', methods=['GET', 'POST'])
@login_required
def ui_settings():
    addchecklistform = CreateCheckListForm()
    if addchecklistform.validate_on_submit():
        api.samplecontrol.create_checklist(addchecklistform.title.data,
                                           addchecklistform.description.data)
    return render_template("settings.html",
                           addchecklistform=addchecklistform,
                           checklists=api.samplecontrol.get_all_checklists(),
                           users=api.usercontrol.get_all())


@app.route('/settings/deletechecklist/<int:checklist_id>', methods=['GET'])
@login_required
def deletechecklist(checklist_id):
    """
    Delete a checklist element.
    """
    checklist_item = api.samplecontrol.get_checklist_by_id(checklist_id)
    if not checklist_item:
        abort(404)
    api.samplecontrol.delete_checklist(checklist_item)
    return redirect(url_for('ui_settings'))


@app.route('/user/<int:user_id>/', methods=['GET', 'POST'])
@login_required
def view_user(user_id):
    """
        View a single user activity
        Useful for executive report
    """
    myuser = api.usercontrol.get_by_id(user_id)
    if myuser is None:
        flash("User not found...", "error")
        return redirect(url_for("index"))

    chnickform = ChgNickForm()
    chthemeform = ChgThemeForm()
    chnameform = ChgNameForm()
    chpassform = ChgPassForm()
    if myuser.id == g.user.id:
        if chthemeform.validate_on_submit():
            api.usercontrol.set_theme(myuser, chthemeform.newtheme.data)
        if chnameform.validate_on_submit():
            api.usercontrol.set_name(myuser, chnameform.newname.data)
        if chnickform.validate_on_submit():
            api.usercontrol.set_nick(myuser, chnickform.newnick.data)
        if chpassform.validate_on_submit():
            if api.usercontrol.check_user_pass(
                    myuser, chpassform.oldpass.data):
                api.usercontrol.set_pass(myuser, chpassform.password.data)
    return render_template('user.html',
                           chnickform=chnickform,
                           chthemeform=chthemeform,
                           chpassform=chpassform,
                           chnameform=chnameform,
                           user=myuser)

@app.route('/user/<int:user_id>/activate', methods=['GET', 'POST'])
@login_required
@roles_required("admin")
def activate_user(user_id):
    ret = api.usercontrol.activate(user_id)
    if not ret:
        flash("Cannot activate user", "error")
    else:
        flash("activated user", "success")
    return redirect(url_for("admin_page"))

@app.route('/user/<int:user_id>/deactivate', methods=['GET', 'POST'])
@login_required
@roles_required("admin")
def deactivate_user(user_id):
    ret = api.usercontrol.deactivate(user_id)
    if not ret:
        flash("Cannot deactivate user", "error")
    return redirect(url_for("admin_page"))

"""

    FAMILIES VIEW

"""


@app.route('/families/', methods=['GET', 'POST'])
@login_required
def view_families():
    """
    Displays the families and handles the root families creation.
    """
    familycreationform = FamilyForm()
    if familycreationform.validate_on_submit():
        api.familycontrol.create(name=familycreationform.familyname.data)
    return render_template("families.html",
                           myfamilies=api.familycontrol.get_all(),
                           form=familycreationform)

"""

    FAMILY VIEW

"""


@app.route('/family/<int:family_id>/', methods=['GET', 'POST'])
@login_required
def view_family(family_id):
    """
    Family view and forms handling.
    """
    family = api.familycontrol.get_by_id(family_id)
    if family is None:
        abort(404)

    family_users = api.familycontrol.get_users_for_family(family)
    export_form = ExportFamilyForm()
    add_subfamily_form = AddSubFamilyForm()
    add_yara_form = AddYaraToFamilyForm()
    yara_choices = [(f.id, f.name) for f in YaraRule.query.order_by(
        'name') if f not in family.yaras]
    add_yara_form.yaraid.choices = yara_choices
    family_abstract_form = FamilyAbstractForm()
    add_detection_item_form = CreateDetectionItemForm()
    change_status_form = ChangeStatusForm()
    change_tlp_form = ChangeTLPForm()
    add_attachment_form = UploadFamilyFileForm()

    if add_subfamily_form.validate_on_submit():
        newname = add_subfamily_form.familyname.data
        newname = family.name + "." + newname
        fid = api.familycontrol.create(name=newname, parentfamily=family)
        if not fid:
            abort(500)

    if export_form.validate_on_submit():
        exptype = export_form.datatype.data
        lvl = export_form.level.data
        if exptype == 1:
            return redirect(
                url_for(
                    "apiview.api_family_export_detection_yara",
                    family_id=family.id,
                    tlp_level=lvl))
        elif exptype == 2:
            return redirect(
                url_for(
                    "apiview.api_family_export_samplesioc",
                    family_id=family.id,
                    tlp_level=lvl))
        elif exptype == 3:
            return redirect(
                url_for(
                    "apiview.api_family_export_detection_openioc",
                    family_id=family.id,
                    tlp_level=lvl))
        elif exptype == 4:
            return redirect(
                url_for(
                    "apiview.api_family_export_detection_snort",
                    family_id=family.id,
                    tlp_level=lvl))
        elif exptype == 5:
            return redirect(
                url_for(
                    "apiview.api_family_export_detection_custom_elements",
                    family_id=family.id,
                    tlp_level=lvl))
        elif exptype == 6:
            return redirect(
                url_for(
                    "apiview.api_family_export_sampleszip",
                    family_id=family.id,
                    tlp_level=lvl))
    if add_yara_form.validate_on_submit():
        yar = api.yaracontrol.get_by_id(add_yara_form.yaraid.data)
        if yar is not None:
            api.yaracontrol.add_to_family(family, yar)
    if family_abstract_form.validate_on_submit():
        abstract = family_abstract_form.abstract.data
        api.familycontrol.set_abstract(family, abstract)
    elif family.abstract is not None:
        family_abstract_form.abstract.default = family.abstract
        family_abstract_form.abstract.data = family.abstract
    if change_tlp_form.validate_on_submit():
        level = change_tlp_form.level.data
        api.familycontrol.set_tlp_level(family, level)
    if change_status_form.validate_on_submit():
        status = change_status_form.newstatus.data
        api.familycontrol.set_status(family, status)
    if add_detection_item_form.validate_on_submit():
        api.familycontrol.create_detection_item(
            add_detection_item_form.abstract.data,
            add_detection_item_form.name.data,
            add_detection_item_form.tlp_level.data,
            add_detection_item_form.item_type.data,
            family)
    if add_attachment_form.validate_on_submit():
        data = add_attachment_form.file.data.read()
        fname = secure_filename(add_attachment_form.file.data.filename)
        api.familycontrol.add_file(data,
                                   fname,
                                   add_attachment_form.description.data,
                                   add_attachment_form.level.data,
                                   family)

    return render_template("family.html",
                           family=family,
                           expform=export_form,
                           addsubfamform=add_subfamily_form,
                           uploadform=add_attachment_form,
                           abstractform=family_abstract_form,
                           createdetectionitemform=add_detection_item_form,
                           changestatusform=change_status_form,
                           changetlpform=change_tlp_form,
                           famusers=family_users,
                           yaraform=add_yara_form)


@app.route('/family/<int:family_id>/downloadfile/<int:file_id>/')
@login_required
def download_family_file(family_id, file_id):
    """
    Family attachment download endpoint. Not in API for now, but may be
    migrated soon.
    TODO: serve file instead of reading and sending raw headers.
    """
    family = api.familycontrol.get_by_id(family_id)
    attachment = api.familycontrol.get_file_by_id(file_id)
    if family is None or attachment is None:
        abort(404)
    if not os.path.exists(attachment.filepath):
        abort(404)
    file_data = open(attachment.filepath, "rb").read()
    response = make_response(file_data)
    response.headers["Content-type"] = "application/octet-stream"
    response.headers[
        "Content-Disposition"] = "attachment; filename=" + attachment.filename
    return response


@app.route("/family/<int:family_id>/addreme/")
@login_required
def add_remove_me(family_id):
    """
    Add or remove the current user to the families referents.
    """
    family = api.familycontrol.get_by_id(family_id)
    if family is None:
        abort(404)
    if g.user in family.users:
        api.familycontrol.remove_user(g.user, family)
    else:
        api.familycontrol.add_user(g.user, family)
    return redirect(url_for('view_family', family_id=family_id))


@app.route('/family/<int:family_id>/deletefile/<int:file_id>/')
@login_required
def delete_family_file(family_id, file_id):
    """
    Delete a family attached file.
    """
    family = api.familycontrol.get_by_id(family_id)
    attachment = api.familycontrol.get_file_by_id(file_id)
    if family is None or attachment is None:
        abort(404)
    api.familycontrol.delete_file(attachment)
    return redirect(url_for('view_family', family_id=family.id))


@app.route('/family/<int:family_id>/deleteyara/<int:yara_id>', methods=['GET'])
@login_required
def delete_yara_family(family_id, yara_id):
    """
    Deletes an associated yara rule.
    """
    family = api.familycontrol.get_by_id(family_id)
    yar = api.yaracontrol.get_by_id(yara_id)
    if family is None or yar is None:
        abort(404)
    api.yaracontrol.remove_to_family(family, yar)
    return redirect(url_for("view_family", family_id=family_id))


@app.route('/family/<int:family_id>/deleteitem/<int:item_id>/')
@login_required
def delete_family_item(family_id, item_id):
    """
    Delete a family detection item.
    """
    family = api.familycontrol.get_by_id(family_id)
    detection_item = api.familycontrol.get_detection_item_by_id(item_id)
    if family is None or detection_item is None:
        abort(404)
    api.familycontrol.delete_detection_item(detection_item)
    return redirect(url_for('view_family', family_id=family.id))


@app.route('/family/<int:family_id>/delete/')
@login_required
def delete_family(family_id):
    """
    Delete a family.
    """
    family = api.familycontrol.get_by_id(family_id)
    parentfamily = None
    if family is None:
        abort(404)
    parentfamily = family.parents
    api.familycontrol.delete(family)
    if parentfamily is not None:
        return redirect(url_for('view_family', family_id=parentfamily.id))
    return redirect(url_for('view_families'))


"""

    SAMPLE VIEW

"""


@app.route('/samples/', methods=['GET', 'POST'])
@login_required
def ui_sample_upload():
    """
    Sample creation from binary file.
    """
    upload_form = UploadSampleForm()
    families_choices = [(0, "None")]
    families_choices += [(f.id, f.name) for f in Family.query.order_by('name')]
    upload_form.family.choices = families_choices
    if upload_form.validate_on_submit():
        file_data = upload_form.file.data
        family_id = upload_form.family.data
        family = None
        if family_id != 0:
            family = api.familycontrol.get_by_id(family_id)
            if family is None:
                abort(404)
        file_name = secure_filename(upload_form.file.data.filename)
        sample = api.create_sample_and_run_analysis(
            file_data, file_name, g.user, upload_form.level.data, family)
        if sample:
            return redirect(url_for('view_sample', sample_id=sample.id))
    return redirect(url_for('index'))


@app.route('/import/', methods=['GET', 'POST'])
@login_required
def ui_import():
    """
    Sample creation from MACHEX data.
    """
    machex_import_form = ImportForm()
    if machex_import_form.validate_on_submit():
        machex_data = machex_import_form.file.data.read()
        tlp_level = machex_import_form.level.data
        sample = api.samplecontrol.create_sample_from_json_machex(
            machex_data, tlp_level)
        if sample:
            return redirect(url_for('view_sample', sample_id=sample.id))
    return redirect(url_for('index'))


def gen_sample_view(sample_id, graph=None, fctaddr=None):
    """
    Generates a sample's view (template). We split the view because of the
    disassembly view, which is directly included in the sample's view, but
    not "by default".
    """
    sample = api.samplecontrol.get_by_id(sample_id)
    if sample is None:
        abort(404)
    machex_export_form = ExportMachexForm(sampleid=sample.id)
    set_sample_abstract_form = SampleAbstractForm()
    add_family_form = AddSampleToFamilyForm()
    families_choices = [(f.id, f.name) for f in Family.query.order_by('name')]
    add_family_form.parentfamily.choices = families_choices
    change_tlp_level_form = ChangeTLPForm()
    machoc_compare_form = CompareMachocForm()
    sample_metadata = []
    for i in sample.s_metadata:
        sample_metadata.append(
            {"type": SampleMetadataType.tostring(i.type_id), "value": i.value})

    if add_family_form.validate_on_submit():
        family_id = add_family_form.parentfamily.data
        family = api.familycontrol.get_by_id(family_id)
        if family is None:
            abort(404)
        api.familycontrol.add_sample(sample, family)
    if set_sample_abstract_form.validate_on_submit():
        abstract = set_sample_abstract_form.abstract.data
        api.samplecontrol.set_abstract(sample, abstract)
    elif sample.abstract is not None:
        set_sample_abstract_form.abstract.default = sample.abstract
        set_sample_abstract_form.abstract.data = sample.abstract
    if change_tlp_level_form.validate_on_submit():
        level = change_tlp_level_form.level.data
        api.samplecontrol.set_tlp_level(sample, level)
    machoc_comparison_results = None
    if machoc_compare_form.validate_on_submit():
        comparison_level = machoc_compare_form.percent.data
        if comparison_level < 1:
            comparison_level = 1
        elif comparison_level > 100:
            comparison_level = 100
        comparison_level = float(comparison_level) / 100
        machoc_comparison_results = api.samplecontrol.machoc_diff_with_all_samples(
            sample, comparison_level)

    return render_template("sample.html",
                           sample=sample,
                           abstractform=set_sample_abstract_form,
                           checklists=api.samplecontrol.get_all_checklists(),
                           changetlpform=change_tlp_level_form,
                           compareform=machoc_compare_form,
                           expform=machex_export_form,
                           hresults=machoc_comparison_results,
                           metasample=sample_metadata,
                           addfamilyform=add_family_form,
                           graph=graph,
                           fctaddr=fctaddr)


@app.route('/sample/<int:sample_id>/', methods=['GET', 'POST'])
@login_required
def view_sample(sample_id):
    """
    Simple view: no disassembly.
    """
    return gen_sample_view(sample_id)


@app.route('/sample/<int:sid>/disassemble/<address>')
@login_required
def ui_disassemble_sample(sid, address):
    """
    Disassemble a particular routine.
    """
    try:
        integer_address = int(address, 16)
    except:
        abort(500)
    """
    Disassembly is not performed by function, but by address: maybe
    the user wants to disass a not-recognized address.
    """
    svg_data = disassemble_sample_get_svg(sid, integer_address)
    return gen_sample_view(sid, graph=svg_data, fctaddr=hex(integer_address))


@app.route('/machexport/', methods=['POST'])
@login_required
def machexport():
    """
    Machex export form handling.
    """
    machex_export_form = ExportMachexForm()
    if machex_export_form.validate_on_submit():
        sample_id = machex_export_form.sampleid.data
        sample = api.samplecontrol.get_by_id(sample_id)
        if sample is None:
            abort(404)
        fnamexp = False
        fmachexp = False
        fstringexp = False
        fmeta = False
        aabstract = False
        sabstract = False
        fullmachoc = False
        if machex_export_form.machocfull.data:
            fullmachoc = True
        if machex_export_form.estrings.data:
            fstringexp = True
        if machex_export_form.metadata.data:
            fmeta = True
        if machex_export_form.fnames.data:
            fnamexp = True
        if machex_export_form.fmachoc.data:
            fmachexp = True
        if machex_export_form.abstracts.data:
            sabstract = True
        if machex_export_form.analysis_data.data:
            aabstract = True
        retv = api.samplecontrol.machexport(sample,
                                            machocfull=fullmachoc,
                                            strings=fstringexp,
                                            metadata=fmeta,
                                            fmachoc=fmachexp,
                                            fname=fnamexp,
                                            sabstract=sabstract,
                                            aabstracts=aabstract)
        return jsonify(retv)


@app.route('/machocdiff/<int:sample_id>/<int:sample2_id>/',
           methods=['GET', 'POST'])
@login_required
def diff_samples(sample_id, sample2_id):
    """
    Diff two samples using MACHOC. Maybe we could move this view in the sample
    view, just as we did for the disassemble view?
    """
    sample1 = api.samplecontrol.get_by_id(sample_id)
    if sample1 is None:
        abort(500)
    sample2 = api.samplecontrol.get_by_id(sample2_id)
    if sample2 is None:
        abort(500)
    sdiff = []
    # POST request means that the samples names sharing has been submitted.
    if request.method == "POST":
        if not request.form.getlist("selectl"):
            abort(500)
        items = []
        for i in request.form.getlist("selectl"):
            n = i.split("_")
            if len(n) == 2:
                items.append((n[0], n[1]))
        if not api.samplecontrol.sample_rename_from_diff(
                items, sample1, sample2):
            abort(500)
        if not api.add_actions_fromfunc_infos(items, sample1, sample2):
            abort(500)
        return redirect("/sample/" + str(sample1.id) + "#poli_infos")
    else:
        sdiff = api.samplecontrol.machoc_get_similar_functions(
            sample1, sample2)
    return render_template("diff.html",
                           sample1=sample1,
                           sample2=sample2,
                           sdiff=sdiff)


@app.route("/sample/<int:sample_id>/checkfield/<int:checklist_id>")
@login_required
def check_field(sample_id, checklist_id):
    """
    Check or uncheck a checklist element.
    """
    sample = api.samplecontrol.get_by_id(sample_id)
    checklist = api.samplecontrol.get_checklist_by_id(checklist_id)
    if sample is None or checklist is None:
        abort(404)
    api.samplecontrol.toggle_sample_checklist(sample, checklist)
    return redirect(url_for('view_sample', sample_id=sample_id))


@app.route("/sample/<int:sample_id>/addreme/")
@login_required
def add_remove_me_samp(sample_id):
    """
    Add or remove the current user to the sample's users.
    """
    sample = api.samplecontrol.get_by_id(sample_id)
    if sample is None:
        abort(404)
    if g.user in sample.users:
        api.samplecontrol.remove_user(g.user, sample)
    else:
        api.samplecontrol.add_user(g.user, sample)
    return redirect(url_for('view_sample', sample_id=sample_id))


@app.route('/sample/<int:sample_id>/removefam/<int:family_id>')
@login_required
def ui_sample_remove_family(sample_id, family_id):
    """
    Add or remove the current user to the sample's users.
    """
    sample = api.samplecontrol.get_by_id(sample_id)
    if sample is not None:
        family = api.familycontrol.get_by_id(family_id)
        if family is not None:
            api.familycontrol.remove_sample(sample, family)
    else:
        abort(404)
    return redirect(url_for('view_sample', sample_id=sample_id))


@app.route('/sample/<int:sample_id>/delete/')
@login_required
def delete_sample(sample_id):
    """
    Delete from DB.
    """
    sample = api.samplecontrol.get_by_id(sample_id)
    if sample is not None:
        api.samplecontrol.delete(sample)
    else:
        abort(404)
    return redirect(url_for('index'))


@app.route('/sample/<int:sample_id>/download/')
@login_required
def download_sample(sample_id):
    """
        Download a sample's file.
    """
    return redirect(url_for('apiview.api_get_sample_file', sid=sample_id))


"""

    SEARCH VIEW

"""


@app.route('/search/', methods=['GET', 'POST'])
@login_required
def ui_search():
    """
    Search and handle forms.
    """
    hform = HashSearchForm()
    tform = FullTextSearchForm()
    mhform = MachocHashSearchForm()
    cfields = []
    i = 1
    while True:
        x = SampleMetadataType.tostring(i)
        if x == "":
            break
        cfields.append(x)
        i = i + 1

    hash_compare_results = None
    samples_results = None
    functions_results = None
    if hform.validate_on_submit():
        hneedle = hform.hneedle.data
        samples_results, functions_results = api.samplecontrol.search_hash(
            hneedle)
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
                           cfields=cfields,
                           mresults=functions_results,
                           hresults=hash_compare_results,
                           results=samples_results)


"""

    YARA SIGNATURES

"""


@app.route('/signatures/', methods=['GET', 'POST'])
@login_required
def ui_yara():
    """
    Yara signatures view.
    """
    create_yara_form = YaraForm()
    change_tlp_level_form = ChangeTLPForm()
    rename_yara_form = RenameForm()

    if create_yara_form.validate_on_submit():
        api.yaracontrol.create(
            create_yara_form.yara_name.data,
            create_yara_form.yara_raw.data,
            create_yara_form.yara_tlp.data)
    if change_tlp_level_form.validate_on_submit():
        if change_tlp_level_form.item_id:
            yar = api.yaracontrol.get_by_id(change_tlp_level_form.item_id.data)
            if yar is None:
                abort(404)
            api.yaracontrol.set_tlp_level(
                change_tlp_level_form.level.data, yar)
    if rename_yara_form.validate_on_submit():
        if rename_yara_form.item_id:
            yar = api.yaracontrol.get_by_id(rename_yara_form.item_id.data)
            if yar is None:
                abort(404)
            api.yaracontrol.rename(rename_yara_form.newname.data, yar)

    yaras = api.yaracontrol.get_all()
    return render_template("signatures.html",
                           myyaras=yaras,
                           changetlpform=change_tlp_level_form,
                           renameform=rename_yara_form,
                           yaraform=create_yara_form)


@app.route('/signatures/delete/<int:sig_id>')
@login_required
def ui_delete_yara(sig_id):
    """
    Delete YARA rule.
    """
    yar = api.yaracontrol.get_by_id(sig_id)
    if not yar:
        abort(404)
    api.yaracontrol.delete(yar)
    return redirect(url_for('ui_yara'))
