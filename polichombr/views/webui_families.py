"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Routes and forms parsing related to families
"""


from flask_security import login_required
from werkzeug import secure_filename
from flask import render_template, g, redirect, url_for, flash

from polichombr import api

from polichombr.models.yara_rule import YaraRule

from polichombr.views.forms import FamilyForm, ExportFamilyForm
from polichombr.views.forms import FamilyAbstractForm, AddYaraToFamilyForm
from polichombr.views.forms import AddSubFamilyForm, UploadFamilyFileForm
from polichombr.views.forms import ChangeTLPForm, ChangeStatusForm
from polichombr.views.forms import CreateDetectionItemForm, RenameForm

from polichombr.views.webui import webuiview


class FamilyFormCheckers(object):
    """
        Parses  the form checkers and family callbacks
    """

    @staticmethod
    def check_form(family, form, callback):
        if form.validate_on_submit():
            callback(family, form)

    @staticmethod
    def family_parse_export_form(family, export_form):
        """
            Parse the export form and redirects to the correct api endpoint
        """
        exptype = export_form.datatype.data
        lvl = export_form.export_level.data

        exptypes = {
            1: "apiview.api_family_export_detection_yara",
            2: "apiview.api_family_export_samplesioc",
            3: "apiview.api_family_export_detection_openioc",
            4: "apiview.api_family_export_detection_snort",
            5: "apiview.api_family_export_detection_custom_elements",
            6: "apiview.api_family_export_sampleszip",
            }

        if exptype not in exptypes.keys():
            flash("Export type not implemented")
            return redirect(url_for("webui.view_family"), family_id=family.id)
        return redirect(url_for(exptypes[exptype],
                                family_id=family.id,
                                tlp_level=lvl))

    @staticmethod
    def family_parse_attachment(family, form):
        data = form.file.data.read()
        fname = secure_filename(form.file.data.filename)
        api.familycontrol.add_file(data,
                                   fname,
                                   form.description.data,
                                   form.level.data,
                                   family)

    @staticmethod
    def family_parse_subfamily(family, form):
        newname = form.subfamilyname.data
        newname = family.name + "." + newname
        fid = api.familycontrol.create(name=newname, parentfamily=family)
        if not fid:
            flash("Error could not create sub family")

    @staticmethod
    def family_parse_yara(family, form):
        yar = api.get_elem_by_type("yara", form.yaraid.data)
        api.yaracontrol.add_to_family(family, yar)

    @staticmethod
    def family_parse_abstract(family, form):
        abstract = form.abstract.data
        api.familycontrol.set_abstract(family, abstract)
        if family.abstract is not None:
                form.abstract.default = family.abstract
                form.abstract.data = family.abstract

    @staticmethod
    def family_parse_tlp(family, form):
        level = form.level.data
        if not api.familycontrol.set_tlp_level(family, level):
            flash("Cannot change family TLP level")

    @staticmethod
    def family_parse_status(family, form):
        status = form.newstatus.data
        api.familycontrol.set_status(family, status)

    @staticmethod
    def family_parse_detection(family, form):
        api.familycontrol.create_detection_item(
            form.item_abstract.data,
            form.name.data,
            form.tlp_level.data,
            form.item_type.data,
            family)

    @staticmethod
    def family_parse_rename(family, form):
        newname = form.newname
        api.familycontrol.rename(family.id, newname.data)


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
                           form=familycreationform)


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
    rename_form = RenameForm()

    FamilyFormCheckers.check_form(family,
                                  rename_form,
                                  FamilyFormCheckers.family_parse_rename)

    FamilyFormCheckers.check_form(family,
                                  add_subfamily_form,
                                  FamilyFormCheckers.family_parse_subfamily)
    FamilyFormCheckers.check_form(family,
                                  add_yara_form,
                                  FamilyFormCheckers.family_parse_yara)

    FamilyFormCheckers.check_form(family,
                                  family_abstract_form,
                                  FamilyFormCheckers.family_parse_abstract)

    FamilyFormCheckers.check_form(family,
                                  change_tlp_form,
                                  FamilyFormCheckers.family_parse_tlp)
    FamilyFormCheckers.check_form(family,
                                  change_status_form,
                                  FamilyFormCheckers.family_parse_status)
    FamilyFormCheckers.check_form(family,
                                  add_detection_item_form,
                                  FamilyFormCheckers.family_parse_detection)
    FamilyFormCheckers.check_form(family, add_attachment_form,
                                  FamilyFormCheckers.family_parse_attachment)

    if export_form.validate_on_submit():
        return FamilyFormCheckers.family_parse_export_form(family,
                                                           export_form)

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
                           renameform=rename_form,
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
