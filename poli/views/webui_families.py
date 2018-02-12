"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Routes and forms parsing related to families
"""


from flask import render_template, g, redirect, url_for, flash
from flask import abort
from flask_security import login_required
from werkzeug import secure_filename

from poli import api

from poli.models.yara_rule import YaraRule

from poli.views.forms import FamilyForm, ExportFamilyForm
from poli.views.forms import FamilyAbstractForm, AddYaraToFamilyForm
from poli.views.forms import AddSubFamilyForm, UploadFamilyFileForm
from poli.views.forms import ChangeTLPForm, ChangeStatusForm
from poli.views.forms import CreateDetectionItemForm

from poli.views.webui import webuiview


@webuiview.route('/families/', methods=['GET', 'POST'])
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


def family_manage_export_form(family_id, export_form):
    """
        TODO
    """
    exptype = export_form.datatype.data
    lvl = export_form.level.data
    if exptype == 1:
        return redirect(
            url_for(
                "apiview.api_family_export_detection_yara",
                family_id=family_id,
                tlp_level=lvl))
    elif exptype == 2:
        return redirect(
            url_for(
                "apiview.api_family_export_samplesioc",
                family_id=family_id,
                tlp_level=lvl))
    elif exptype == 3:
        return redirect(
            url_for(
                "apiview.api_family_export_detection_openioc",
                family_id=family_id,
                tlp_level=lvl))
    elif exptype == 4:
        return redirect(
            url_for(
                "apiview.api_family_export_detection_snort",
                family_id=family_id,
                tlp_level=lvl))
    elif exptype == 5:
        return redirect(
            url_for(
                "apiview.api_family_export_detection_custom_elements",
                family_id=family_id,
                tlp_level=lvl))
    elif exptype == 6:
        return redirect(
            url_for(
                "apiview.api_family_export_sampleszip",
                family_id=family_id,
                tlp_level=lvl))
    return abort("Not implemented", 500)


@webuiview.route('/family/<int:family_id>/', methods=['GET', 'POST'])
@login_required
def view_family(family_id):
    """
    Family view and forms handling.
    """
    family = api.get_elem_by_type("family", family_id)

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
        family_manage_export_form(family.id, export_form)
    if add_yara_form.validate_on_submit():
        yar = api.get_elem_by_type("yara", add_yara_form.yaraid.data)
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
            add_detection_item_form.item_abstract.data,
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


@webuiview.route("/family/<int:family_id>/addreme/")
@login_required
def add_remove_me(family_id):
    """
    Add or remove the current user to the families referents.
    """
    family_id = api.remove_user_from_element("family",
                                             family_id,
                                             g.user)
    return redirect(url_for('webuiview.view_family', family_id=family_id))


@webuiview.route('/family/<int:family_id>/deletefile/<int:file_id>/')
@login_required
def delete_family_file(family_id, file_id):
    """
    Delete a family attached file.
    """
    family = api.get_elem_by_type("family", family_id)
    attachment = api.get_elem_by_type("family_file", file_id)
    api.familycontrol.delete_file(attachment)
    return redirect(url_for('webuiview.view_family', family_id=family.id))


@webuiview.route('/family/<int:family_id>/deleteyara/<int:yara_id>',
                 methods=['GET'])
@login_required
def delete_yara_family(family_id, yara_id):
    """
    Deletes an associated yara rule.
    """
    family = api.get_elem_by_type("family", family_id)
    yar = api.get_elem_by_type("yara", yara_id)
    api.yaracontrol.remove_from_family(family, yar)
    flash("Removed yara %s from family %s" % (yar.name, family.name),
          "success")
    return redirect(url_for('webuiview.view_family', family_id=family_id))


@webuiview.route('/family/<int:family_id>/deleteitem/<int:item_id>/')
@login_required
def delete_family_item(family_id, item_id):
    """
    Delete a family detection item.
    """
    family = api.get_elem_by_type("family", family_id)
    detection_item = api.get_elem_by_type("detection_item", item_id)
    api.familycontrol.delete_detection_item(detection_item)
    return redirect(url_for('webuiview.view_family', family_id=family.id))


@webuiview.route('/family/<int:family_id>/delete/')
@login_required
def delete_family(family_id):
    """
    Delete a family.
    """
    family = api.get_elem_by_type("family", family_id)
    parentfamily = None
    parentfamily = family.parents
    api.familycontrol.delete(family)
    flash("Deleted family", "success")
    if parentfamily is not None:
        return redirect(url_for('webuiview.view_family',
                                family_id=parentfamily.id))
    return redirect(url_for('webuiview.view_families'))
