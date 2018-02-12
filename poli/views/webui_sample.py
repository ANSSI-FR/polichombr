"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Routes and forms parsing related to stored samples
"""

from flask import render_template, g, redirect, url_for, flash
from flask import abort, request, jsonify

from werkzeug import secure_filename
from flask_security import login_required

from poli import api

from poli.views.webui import webuiview

from poli.models.family import Family

from poli.views.forms import SampleAbstractForm, UploadSampleForm
from poli.views.forms import AddSampleToFamilyForm, ChangeTLPForm
from poli.views.forms import ImportForm, ExportMachexForm
from poli.views.forms import CompareMachocForm

from poli.controllers.sample import disassemble_sample_get_svg


@webuiview.route('/samples/', methods=['GET', 'POST'])
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
        family_id = upload_form.family.data
        zipflag = upload_form.zipflag.data
        family = None
        if family_id != 0:
            family = api.get_elem_by_type("family", family_id)

        for mfile in upload_form.files.raw_data:
            file_data = mfile.stream
            file_name = secure_filename(mfile.filename)

            samples = api.dispatch_sample_creation(
                file_data,
                file_name,
                g.user,
                upload_form.level.data,
                family,
                zipflag)
            if not samples:
                flash("Error during sample creation", "error")
            else:
                for sample in samples:
                    flash("Created sample " + str(sample.id), "success")
    return redirect(url_for('webuiview.index'))


@webuiview.route('/import/', methods=['GET', 'POST'])
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
            return redirect(url_for('webuiview.view_sample', sample_id=sample.id))
    return redirect(url_for('webuiview.index'))


def parse_machoc_form(sample, form):
    """
        Returns the matches results
    """
    comparison_level = form.percent.data
    if comparison_level < 1:
        comparison_level = 1
    elif comparison_level > 100:
        comparison_level = 100
    comparison_level = float(comparison_level) / 100
    results = api.samplecontrol.machoc_diff_with_all_samples(
        sample, comparison_level)
    return results


def gen_sample_view(sample_id, graph=None, fctaddr=None):
    """
    Generates a sample's view (template). We split the view because of the
    disassembly view, which is directly included in the sample's view, but
    not "by default".
    """
    sample = api.get_elem_by_type("sample", sample_id)
    machex_export_form = ExportMachexForm(sampleid=sample.id)
    set_sample_abstract_form = SampleAbstractForm()
    add_family_form = AddSampleToFamilyForm()
    families_choices = [(f.id, f.name) for f in Family.query.order_by('name')]
    add_family_form.parentfamily.choices = families_choices
    change_tlp_level_form = ChangeTLPForm()
    machoc_form = CompareMachocForm()

    if add_family_form.validate_on_submit():
        family_id = add_family_form.parentfamily.data
        family = api.get_elem_by_type("family", family_id)
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
    if machoc_form.validate_on_submit():
        machoc_comparison_results = parse_machoc_form(sample, machoc_form)

    return render_template("sample.html",
                           sample=sample,
                           abstractform=set_sample_abstract_form,
                           checklists=api.samplecontrol.get_all_checklists(),
                           changetlpform=change_tlp_level_form,
                           compareform=machoc_form,
                           expform=machex_export_form,
                           hresults=machoc_comparison_results,
                           addfamilyform=add_family_form,
                           graph=graph,
                           fctaddr=fctaddr)


@webuiview.route('/sample/<int:sample_id>/', methods=['GET', 'POST'])
@login_required
def view_sample(sample_id):
    """
    Simple view: no disassembly.
    """
    return gen_sample_view(sample_id)


@webuiview.route('/sample/<int:sid>/disassemble/<address>')
@login_required
def ui_disassemble_sample(sid, address):
    """
    Disassemble a particular routine.
    """
    try:
        integer_address = int(address, 16)
    except BaseException:
        abort(500)
    """
    Disassembly is not performed by function, but by address: maybe
    the user wants to disass a not-recognized address.
    """
    svg_data = disassemble_sample_get_svg(sid, integer_address)
    return gen_sample_view(sid, graph=svg_data, fctaddr=hex(integer_address))


@webuiview.route('/samples/<int:sample_id>/machexport/', methods=['POST'])
@login_required
def machexport(sample_id):
    """
    Machex export form handling.
    """
    machex_export_form = ExportMachexForm()
    sample = api.get_elem_by_type("sample", sample_id)
    if machex_export_form.validate_on_submit():
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
    return abort(400)


@webuiview.route('/machocdiff/<int:sample_id>/<int:sample2_id>/',
           methods=['GET', 'POST'])
@login_required
def diff_samples(sample_id, sample2_id):
    """
    Diff two samples using MACHOC. Maybe we could move this view in the sample
    view, just as we did for the disassemble view?
    """
    sample1 = api.get_elem_by_type("sample", sample_id)
    sample2 = api.get_elem_by_type("sample", sample2_id)
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


@webuiview.route("/sample/<int:sample_id>/checkfield/<int:checklist_id>/")
@login_required
def check_field(sample_id, checklist_id):
    """
    Check or uncheck a checklist element.
    """
    sample = api.get_elem_by_type("sample", sample_id)
    checklist = api.get_elem_by_type("checklist", checklist_id)
    api.samplecontrol.toggle_sample_checklist(sample, checklist)
    return redirect(url_for('webuiview.view_sample', sample_id=sample_id))


@webuiview.route("/sample/<int:sample_id>/addreme/")
@login_required
def add_remove_me_samp(sample_id):
    """
    Add or remove the current user to the sample's users.
    """
    api.remove_user_from_element("sample",
                                 sample_id,
                                 g.user)
    return redirect(url_for('webuiview.view_sample', sample_id=sample_id))


@webuiview.route('/sample/<int:sample_id>/removefam/<int:family_id>')
@login_required
def ui_sample_remove_family(sample_id, family_id):
    """
    Add or remove the current user to the sample's users.
    """
    sample = api.get_elem_by_type("sample", sample_id)
    family = api.get_elem_by_type("family", family_id)
    api.familycontrol.remove_sample(sample, family)
    return redirect(url_for('webuiview.view_sample', sample_id=sample_id))


@webuiview.route('/sample/<int:sample_id>/delete/')
@login_required
def delete_sample(sample_id):
    """
    Delete from DB.
    """
    sample = api.get_elem_by_type("sample", sample_id)
    api.samplecontrol.delete(sample)
    return redirect(url_for('webuiview.index'))


@webuiview.route('/sample/<int:sample_id>/download/')
@login_required
def download_sample(sample_id):
    """
        Download a sample's file.
    """
    return redirect(url_for('apiview.api_get_sample_file', sid=sample_id))
