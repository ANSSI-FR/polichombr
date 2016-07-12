"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Contains all the model for the samples,
        including the corresponding relations
"""

from marshmallow import fields

from poli import db, ma

from poli.models.models import TLPLevel
from poli.models.analysis import AnalysisResultSchema


class SampleMetadata(db.Model):
    """
        Generic table used to store generic file metadata. Type must be
        defined in the SampleMetadataType enum class below. Value contains
        the metadata itself.
    """
    __tablename__ = 'samplemetadata'
    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(db.Integer(), index=True)
    value = db.Column(db.String())
    sample_id = db.Column(db.Integer(), db.ForeignKey("sample.id"))


class SampleMetadataType:
    """
        Possible keys for file metadata.
    """
    (
        PE_DOS_HEADER_e_magic,
        PE_DOS_HEADER_e_cblp,
        PE_DOS_HEADER_e_cp,
        PE_DOS_HEADER_e_crlc,
        PE_DOS_HEADER_e_cparhdr,
        PE_DOS_HEADER_e_minalloc,
        PE_DOS_HEADER_e_maxalloc,
        PE_DOS_HEADER_e_ss,
        PE_DOS_HEADER_e_sp,
        PE_DOS_HEADER_e_csum,
        PE_DOS_HEADER_e_ip,
        PE_DOS_HEADER_e_cs,
        PE_DOS_HEADER_e_lfarlc,
        PE_DOS_HEADER_e_ovno,
        PE_DOS_HEADER_e_res,
        PE_DOS_HEADER_e_oemid,
        PE_DOS_HEADER_e_oeminfo,
        PE_DOS_HEADER_e_res2,
        PE_DOS_HEADER_e_lfanew,
        PE_FILE_HEADER_Machine,
        PE_FILE_HEADER_NumberOfSections,
        PE_FILE_HEADER_TimeDateStamp,
        PE_FILE_HEADER_PointerToSymbolTable,
        PE_FILE_HEADER_NumberOfSymbols,
        PE_FILE_HEADER_SizeOfOptionalHeader,
        PE_FILE_HEADER_Characteristics,
        PE_OPTIONAL_HEADER_Magic,
        PE_OPTIONAL_HEADER_MajorLinkerVersion,
        PE_OPTIONAL_HEADER_MinorLinkerVersion,
        PE_OPTIONAL_HEADER_SizeOfCode,
        PE_OPTIONAL_HEADER_SizeOfInitializedData,
        PE_OPTIONAL_HEADER_SizeOfUninitializedData,
        PE_OPTIONAL_HEADER_AddressOfEntryPoint,
        PE_OPTIONAL_HEADER_BaseOfCode,
        PE_OPTIONAL_HEADER_ImageBase,
        PE_OPTIONAL_HEADER_SectionAlignment,
        PE_OPTIONAL_HEADER_FileAlignment,
        PE_OPTIONAL_HEADER_MajorOperatingSystemVersion,
        PE_OPTIONAL_HEADER_MinorOperatingSystemVersion,
        PE_OPTIONAL_HEADER_MajorImageVersion,
        PE_OPTIONAL_HEADER_MinorImageVersion,
        PE_OPTIONAL_HEADER_MajorSubsystemVersion,
        PE_OPTIONAL_HEADER_MinorSubsystemVersion,
        PE_OPTIONAL_HEADER_Reserved1,
        PE_OPTIONAL_HEADER_SizeOfImage,
        PE_OPTIONAL_HEADER_SizeOfHeaders,
        PE_OPTIONAL_HEADER_CheckSum,
        PE_OPTIONAL_HEADER_Subsystem,
        PE_OPTIONAL_HEADER_DllCharacteristics,
        PE_OPTIONAL_HEADER_SizeOfStackReserve,
        PE_OPTIONAL_HEADER_SizeOfStackCommit,
        PE_OPTIONAL_HEADER_SizeOfHeapReserve,
        PE_OPTIONAL_HEADER_SizeOfHeapCommit,
        PE_OPTIONAL_HEADER_LoaderFlags,
        PE_OPTIONAL_HEADER_NumberOfRvaAndSizes,
        PE_import_hash) = range(1, 57)

    @classmethod
    def tostring(cls, val):
        for k, v in vars(cls).iteritems():
            if v == val:
                return k
        return ""

    @classmethod
    def fromstring(cls, s):
        return getattr(cls, s, None)


class StringsItem(db.Model):
    """
    Strings contained in a binary file. Strings types are defined by the
    StringsType enum class.
    """
    __tablename__ = 'stringsitem'
    id = db.Column(db.Integer, primary_key=True)
    string_type = db.Column(db.Integer(), index=True)
    string_value = db.Column(db.String())
    sample_id = db.Column(db.Integer(), db.ForeignKey("sample.id"))


class StringsType:
    """
    Strings types.
    """
    (
        UNICODE,
        ASCII,
        BUILDED,    # builded on stack
        UNPACKED    # extracted after unpacking in IDAPro
    ) = range(1, 5)

    @classmethod
    def tostring(cls, val):
        for k, v in vars(cls).iteritems():
            if v == val:
                return k
        return ""

    @classmethod
    def fromstring(cls, val):
        return getattr(cls, val, None)


class FunctionInfo(db.Model):
    """
        Function information. Contains function's name, machoc hash and
        address. Used for quick function access. Machoc hash can be
        updated by tasks or by skelenox itself.
    """
    __tablename__ = 'functioninfo'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String())
    name = db.Column(db.String())
    machoc_hash = db.Column(db.Integer(), index=True)
    sample_id = db.Column(db.Integer(), db.ForeignKey("sample.id"))


class SampleMatch(db.Model):
    """
        Match between samples. Used to spot samples similarities on
        analysis. Displayed to user.
    """
    __tablename__ = 'samplematch'
    id = db.Column(db.Integer, primary_key=True)
    sid_1 = db.Column(db.Integer, db.ForeignKey('sample.id'))
    sid_2 = db.Column(db.Integer, db.ForeignKey('sample.id'))
    match_type = db.Column(db.String())


class FileName(db.Model):
    """
        Sample's files names.
    """
    __tablename__ = 'filename'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    sample_id = db.Column(db.Integer(), db.ForeignKey("sample.id"))


class AnalysisStatus:
    """
        Sample's analysis status (enum). Used for analysis scheduling
        and in samples views.
    """
    (
        FINISHED,
        RUNNING,
        TOSTART
    ) = range(1, 4)

    @classmethod
    def tostring(cls, val):
        for k, v in vars(cls).iteritems():
            if v == val:
                return k
        return ""

    @classmethod
    def fromstring(cls, val):
        return getattr(cls, val, None)


class CheckList(db.Model):
    """
        Checklist fields and description. This is a global information,
        set in the admin panel, links will just determine if checked
        or not.
    """
    __tablename__ = 'checklist'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String())
    description = db.Column(db.String())


sampletochecklist = db.Table('sampletochecklist',
                             db.Column('checklist_id',
                                       db.Integer,
                                       db.ForeignKey('checklist.id')),
                             db.Column('sample_id',
                                       db.Integer,
                                       db.ForeignKey('sample.id')))

"""
    Matched Yara rules relationship.
"""
sampletoyara = db.Table('sampletoyara',
                        db.Column('yara_id',
                                  db.Integer,
                                  db.ForeignKey('yararule.id')),
                        db.Column('sample_id',
                                  db.Integer,
                                  db.ForeignKey('sample.id')))

"""
    IDA actions relationship.
"""
sampletoactions = db.Table('sampletoactions',
                           db.Column('sample_id',
                                     db.Integer,
                                     db.ForeignKey('sample.id')),
                           db.Column('action_id',
                                     db.Integer,
                                     db.ForeignKey('idaactions.id')))


class Sample(db.Model):
    """
    Samples model.
    """
    __tablename__ = 'sample'
    id = db.Column(db.Integer, primary_key=True)
    # N-N relationships
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    check_list = db.relationship('CheckList',
                                 secondary=sampletochecklist,
                                 backref=db.backref('samples', lazy='dynamic'))
    actions = db.relationship('IDAAction',
                              secondary=sampletoactions,
                              backref=db.backref('samples', lazy='dynamic'))
    yaras = db.relationship('YaraRule',
                            secondary=sampletoyara,
                            backref=db.backref('samples', lazy='dynamic'))
    # Enriched N-N relationships (double link)
    linked_samples = db.relationship('SampleMatch',
                                     backref=db.backref('sample1',
                                                        remote_side=[id]),
                                     foreign_keys=[SampleMatch.sid_1])
    linked_samples_2 = db.relationship('SampleMatch',
                                       backref=db.backref('sample2',
                                                          remote_side=[id]),
                                       foreign_keys=[SampleMatch.sid_2])
    # 1-N relationships
    strings = db.relationship(
        "StringsItem", backref=db.backref(
            'sample', remote_side=[id]))
    s_metadata = db.relationship(
        "SampleMetadata", backref=db.backref(
            'sample', remote_side=[id]))
    functions = db.relationship(
        "FunctionInfo", backref=db.backref(
            'sample', remote_side=[id]))
    filenames = db.relationship(
        "FileName", backref=db.backref(
            'sample', remote_side=[id]))
    analysis_data = db.relationship(
        'AnalysisResult', backref=db.backref(
            "sample", remote_side=[id]))
    # Sample's binary path
    storage_file = db.Column(db.String())
    # File size
    size = db.Column(db.Integer())
    # File's internal date (compilation timestamp, etc.)
    file_date = db.Column(db.DateTime(), index=True)
    # Hashes
    md5 = db.Column(db.String(32), index=True, nullable=False)
    sha1 = db.Column(db.String(40), index=True, nullable=False)
    sha256 = db.Column(db.String(64), index=True, nullable=False)
    # Mime type
    mime_type = db.Column(db.String())
    full_mime_type = db.Column(db.String())
    # Abstract, set by user
    abstract = db.Column(db.String())
    # Import hash, set by tasks
    import_hash = db.Column(db.String())
    # TLP level, mandatory
    TLP_sensibility = db.Column(
        db.Integer(),
        nullable=False,
        default=TLPLevel.TLPAMBER)
    # Analysis status
    analysis_status = db.Column(
        db.Integer(),
        nullable=False,
        default=AnalysisStatus.TOSTART)
    # Sample's analysis date
    analysis_date = db.Column(db.DateTime())
    # "status" is not used, for now
    # status = db.Column(db.Integer())

    def __repr__(self):
        return 'Sample %d' % self.id


class SampleMatchSchema(ma.ModelSchema):
    """
    Match schema.
    """
    class Meta:
        fields = ('id',
                  'sid_1',
                  'sid_2',
                  'match_type')


class SampleSchema(ma.ModelSchema):
    """
    Sample schema.
    """
    families = fields.Nested('FamilySchema', only=['id', 'name'])
    users = fields.Nested('UserSchema', only=['id', 'nickname'])
    analysis_data = fields.Nested(AnalysisResultSchema,
                                  many=True,
                                  only=['id', 'type'])
    linked_samples = fields.Nested(SampleMatchSchema,
                                   many=True,
                                   only=['sid_2', 'match_type'])

    class Meta:
        """
            See flask-marshmallow doc
        """
        fields = ('id',
                  'md5',
                  'sha1',
                  'sha256',
                  'size',
                  'mime_type',
                  'full_mime_type',
                  'analysis_status',
                  'analysis_date',
                  'file_date',
                  'TLP_sensibility',
                  'linked_samples',
                  'abstract')
