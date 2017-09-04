"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Definition for each analysis result
"""

from poli import db, ma


class AnalysisResult(db.Model):

    """
        Containing all PE analysis data.
    """
    __tablename__ = "analysisresult"
    id = db.Column(db.Integer(), primary_key=True)
    sample_id = db.Column(db.Integer(), db.ForeignKey('sample.id'))
    analysis_status = db.Column(db.Boolean())
    analysis_date = db.Column(db.DateTime())
    title = db.Column(db.String())
    data = db.Column(db.String())
    type = db.Column(db.String())


class AnalysisResultSchema(ma.ModelSchema):

    """
    Export schema.
    """
    class Meta:
        fields = ('id',
                  'analysis_status',
                  'analysis_date',
                  'type')


"""
    <== PE STRUCTS DATA MODELS ==>
    TODO: NOT IMPLEMENTED, task-related.

    NOTES: I think tasks-related models should not be defined in the
    regular Polichombr data models files. We should move these models to
    a "task.py" dedicated file. The peinfo task should then use its own
    routines to populate these tables. The problem is that these models
    are not generic ones, and that their display must be custom. I think
    we can solve the problem by generically import task-defined templates.

    The PEInfo main problem is that the produced information should be
    browsable. If we already can search for imports/exports by searching
    for ASCII strings in the full-text view, it could be interresting to
    search for specific sections. Actually, I see only two solutions:
    1- integrate the PEInfo model to Polichombr, and make the PEInfo task
    mandatory (actually it's delivered with Polichombr);
    2- transform the produced information in generic SampleMetadata items
    (PESection_name = 1_.text , PESectionMisc = 1_0x1234,
    PEImport = kernel32.dll_CreateProcessA, etc.). Ugly.

    1) is the more effective solution as everything will be in the core
    development, but it creates a "precedent", and I do NOT want to
    integrate tasks in the core;
    2) answers the problem, but the metadata view will not be very user
    friendly (especially for sections).

"""


class PEImport(db.Model):
    __tablename__ = 'peimport'
    id = db.Column(db.Integer(), primary_key=True)
    module_name = db.Column(db.String(), index=True)
    function_name = db.Column(db.String())


class PEExport(db.Model):
    __tablename__ = 'peexport'
    id = db.Column(db.Integer(), primary_key=True)
    module_name = db.Column(db.String(), index=True)
    function_name = db.Column(db.String())


class PESection(db.Model):
    __tablename__ = 'pesection'
    id = db.Column(db.Integer(), primary_key=True)
    s_Name = db.Column(db.String(), index=True)
    s_Misc = db.Column(db.Integer())
    s_PhysicalAddress = db.Column(db.Integer())
    s_VirtualSize = db.Column(db.Integer())
    s_VirtualAddress = db.Column(db.Integer())
    s_SizeOfRawData = db.Column(db.Integer())
    s_PointerToRawData = db.Column(db.Integer())
    s_PointerToRelocations = db.Column(db.Integer())
    s_PointerToLineNumbers = db.Column(db.Integer())
    s_NumberOfRelocations = db.Column(db.Integer())
    s_NumberOfLinenumbers = db.Column(db.Integer())
    s_Characteristics = db.Column(db.Integer())
    s_md5 = db.Column(db.String())
