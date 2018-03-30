"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Forms used in the web interface.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, SelectField
from wtforms import SubmitField, TextAreaField, BooleanField
from wtforms import PasswordField, HiddenField
from wtforms import IntegerField
from wtforms.validators import DataRequired, Length, EqualTo
from polichombr.models.family import DetectionType
from polichombr.models.models import TLPLevelChoices


class ChgThemeForm(FlaskForm):

    """
    Change user's theme.
    """
    choices = [
        ("dark", 'dark'),
        ("std", 'regular')
    ]
    newtheme = SelectField('Theme', choices=choices,
                           coerce=str, validators=[DataRequired()])
    changetheme = SubmitField('Submit')


class ChgNickForm(FlaskForm):

    """
    Change user's nickname (login).
    """
    newnick = StringField("New nick", validators=[DataRequired()])
    changenick = SubmitField('Submit')


class ChgNameForm(FlaskForm):

    """
    Change user's full name.
    """
    newname = StringField("New name", validators=[DataRequired()])
    changename = SubmitField('Submit')


class ChgPassForm(FlaskForm):

    """
    Change user's password.
    """
    oldpass = PasswordField("Old password", validators=[DataRequired()])
    password = PasswordField(
        'New password', validators=[
            Length(min=6),
            DataRequired(),
            EqualTo('rpt_pass',
                    message='Confirmation must match')])
    rpt_pass = PasswordField('Confirm password')
    changepass = SubmitField('Submit')


class LoginForm(FlaskForm):

    """
    User login.
    """
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[Length(min=6)])
    userlogin = SubmitField('Submit')


class UserRegistrationForm(FlaskForm):

    """
    User registration.
    """
    username = StringField('Username', validators=[DataRequired()])
    completename = StringField('Complete name', validators=[DataRequired()])
    password = PasswordField(
        'password', validators=[
            Length(min=6),
            DataRequired(),
            EqualTo('rpt_pass',
                    message='Confirmation must match')])
    rpt_pass = PasswordField('Confirm password')
    userregister = SubmitField('Submit')


class CreateCheckListForm(FlaskForm):

    """
    Create new checklist item.
    """
    title = StringField("Title", validators=[DataRequired()])
    description = TextAreaField("Content", validators=[DataRequired()])
    changepoke = SubmitField('Submit')


class YaraForm(FlaskForm):

    """
    Create yara.
    """
    yara_name = StringField('yaraname', validators=[DataRequired()])
    yara_tlp = SelectField('Sensibility', choices=TLPLevelChoices,
                           coerce=int, validators=[DataRequired()])
    yara_raw = TextAreaField('Yaradata', validators=[DataRequired()])
    createyara = SubmitField('Submit')


class FamilyForm(FlaskForm):

    """
    Create family.
    """
    familyname = StringField('familyname',
                             default=None,
                             validators=[DataRequired()])
    createfamily = SubmitField('Submit')


class AddSubFamilyForm(FlaskForm):

    """
    Create sub-family.
    """
    subfamilyname = StringField('Sub-family name', validators=[DataRequired()])
    subfamily = SubmitField('Create')


class UploadFamilyFileForm(FlaskForm):

    """
    Add family file.
    """
    file = FileField('File', validators=[DataRequired()])
    description = StringField('description', validators=[DataRequired()])
    level = SelectField('Sensibility', choices=TLPLevelChoices,
                        coerce=int, validators=[DataRequired()])
    uploadfile = SubmitField('Submit')


class CreateDetectionItemForm(FlaskForm):

    """
    Add detection item.
    """
    name = StringField('Name', validators=[DataRequired()])
    item_abstract = TextAreaField('Abstract', validators=[DataRequired()])
    choices = [
        (DetectionType.CUSTOM, 'Custom'),
        (DetectionType.OPENIOC, 'OpenIOC'),
        (DetectionType.SNORT, 'Snort')
    ]
    item_type = SelectField(
        'Type',
        choices=choices,
        coerce=int,
        validators=[
            DataRequired()])

    tlp_level = SelectField(
        'Sensibility',
        choices=TLPLevelChoices,
        coerce=int,
        validators=[
            DataRequired()])
    createitem = SubmitField('Create')


class ChangeTLPForm(FlaskForm):

    """
    Change TLP level.
    """
    item_id = HiddenField('item_id')
    level = SelectField('', choices=TLPLevelChoices,
                        coerce=int, validators=[DataRequired()])
    changetlp = SubmitField('Change TLP level')


class ChangeStatusForm(FlaskForm):

    """
    Change analysis status.
    """
    choices = [
        (3, 'Not started'),
        (2, 'Currently analyzed'),
        (1, 'Finished'),
    ]
    newstatus = SelectField(
        'Status',
        choices=choices,
        coerce=int,
        validators=[
            DataRequired()])
    changestatus = SubmitField('Change status')


class AddYaraToFamilyForm(FlaskForm):
    """
    Add yara rule.
    """
    yaraid = SelectField(
        'Associated yara',
        coerce=int,
        validators=[
            DataRequired()])
    addyarafam = SubmitField('Submit')


class RenameForm(FlaskForm):
    """
    Rename
    """
    newname = StringField('Name', validators=[DataRequired()])
    item_id = HiddenField('item_id')
    rename = SubmitField('Rename')


class FamilyAbstractForm(FlaskForm):
    """
    Edit abstract.
    """
    abstract = TextAreaField(
        'Family abstract',
        default="Here goes the family informations",
        validators=[
            DataRequired()])
    familyabstract = SubmitField('Submit')


class ExportFamilyForm(FlaskForm):
    """
    Export family data.
    """
    export_level = SelectField('Maximum sensibility', choices=TLPLevelChoices,
                               coerce=int, validators=[DataRequired()])
    choices = [
        (1, "Yara rules (RULESET)"),
        (2, "Samples auto-generated indicators (OPENIOC)"),
        (3, "Custom open-ioc detection items (OPENIOC)"),
        (4, "Custom Snort detection items (SNORT)"),
        (5, "Custom generic detection items (TXT)"),
        (6, "Samples (TARGZ)")
    ]
    datatype = SelectField('Data type', choices=choices,
                           coerce=int, validators=[DataRequired()])
    exportfam = SubmitField('Submit')


class UploadSampleForm(FlaskForm):

    """
    Upload sample.
    """
    files = FileField('Sample File', validators=[DataRequired()],
                      render_kw={'multiple': True})
    level = SelectField('Sensibility', choices=TLPLevelChoices,
                        coerce=int, validators=[DataRequired()])
    family = SelectField('Associated Family', coerce=int)
    zipflag = BooleanField('Sample Zip archive')
    uploadsample = SubmitField('Submit')


class AddSampleToFamilyForm(FlaskForm):

    """
    Add sample to family.
    """
    parentfamily = SelectField(
        'Associated family',
        coerce=int,
        validators=[
            DataRequired()])
    addsample = SubmitField('Submit')


class SampleAbstractForm(FlaskForm):

    """
    Edit abstract.
    """
    abstract = TextAreaField(
        'Sample abstract',
        default="My beautiful sample! ",
        validators=[DataRequired()])
    sampleabstract = SubmitField('Submit')


class CompareMachocForm(FlaskForm):

    """
    Compare to other samples.
    """
    percent = IntegerField('Minimal percent match',
                           validators=[DataRequired()])
    compare = SubmitField('Compare!')


class FullTextSearchForm(FlaskForm):

    """
    Full-text search.
    """
    fneedle = StringField("Search", validators=[DataRequired()])
    full_text_search = SubmitField('Submit')


class MachocHashSearchForm(FlaskForm):

    """
    Full machoc hash search.
    """
    percent = IntegerField("Minimum hit level")
    mneedle = StringField("Search", validators=[DataRequired(),
                                                Length(min=8, max=8)])
    machoc_search = SubmitField('Submit')


class HashSearchForm(FlaskForm):

    """
    Hash search.
    """
    hneedle = StringField("Search", validators=[DataRequired(),
                                                Length(min=32, max=64)])
    hash_search = SubmitField('Submit')
