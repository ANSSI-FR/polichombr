"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Models representing malware families.
"""

from marshmallow import fields

from polichombr import db, ma
from polichombr.models.sample import SampleSchema
from polichombr.models.models import CustomEnum, TLPLevel


class DetectionElement(db.Model):

    """
    Detection element: provided by users, can be any of the DetectionType
    values.
    """
    __tablename__ = "detection_element"
    id = db.Column(db.Integer, primary_key=True)
    abstract = db.Column(db.String())
    name = db.Column(db.String())
    TLP_sensibility = db.Column(db.Integer(), default=TLPLevel.TLPAMBER)
    item_type = db.Column(db.Integer())
    family_id = db.Column(db.Integer(), db.ForeignKey("family.id"))


class DetectionType(CustomEnum):

    """
    Custom family-related detection types.
    """
    (
        CUSTOM,     # raw text
        OPENIOC,    # open ioc format
        SNORT       # snort rule(set)
    ) = list(range(1, 4))


class FamilyDataFile(db.Model):
    """
    Family data file. Whatever you want, script, report, etc.
    """
    __tablename__ = "family_file"
    id = db.Column(db.Integer, primary_key=True)
    filepath = db.Column(db.String())
    filename = db.Column(db.String())
    description = db.Column(db.String())
    TLP_sensibility = db.Column(db.Integer(), default=TLPLevel.TLPAMBER)
    family_id = db.Column(db.Integer(), db.ForeignKey("family.id"))


class FamilyStatus(CustomEnum):
    """
        Is the family analysis complete or not?
    """
    (
        FINISHED,
        CURRENTLY_ANALYZED,
        NOT_STARTED
    ) = list(range(1, 4))


# Yara signatures relationship (auto-classification).
familytoyara = db.Table('familytoyara',
                        db.Column('yara_id', db.Integer,
                                  db.ForeignKey('yararule.id'), index=True),
                        db.Column('family_id', db.Integer,
                                  db.ForeignKey('family.id'), index=True))

# Samples relationship.
familytosample = db.Table('familytosample',
                          db.Column('sample_id', db.Integer,
                                    db.ForeignKey('sample.id'), index=True),
                          db.Column('family_id', db.Integer,
                                    db.ForeignKey('family.id'), index=True))


class Family(db.Model):

    """
    Family model.
    """
    __tablename__ = 'family'

    id = db.Column(db.Integer, primary_key=True)

    # N-N relationships
    samples = db.relationship('Sample',
                              secondary=familytosample,
                              backref=db.backref('families', lazy='dynamic'))
    yaras = db.relationship('YaraRule',
                            secondary=familytoyara,
                            backref=db.backref('families', lazy='dynamic'))
    # 1-N relationships
    parent_id = db.Column(db.Integer, db.ForeignKey('family.id'), index=True)
    subfamilies = db.relationship(
        'Family', backref=db.backref(
            'parents', remote_side=[id]))
    # 1-N relationships, without any backrefs for now
    associated_files = db.relationship('FamilyDataFile')
    detection_items = db.relationship('DetectionElement')
    # Family name's
    name = db.Column(db.String(), index=True)
    # User-supplied abstract
    abstract = db.Column(db.String())
    # Analysis status
    status = db.Column(db.Integer(), default=FamilyStatus.NOT_STARTED)
    # Tlp level
    TLP_sensibility = db.Column(db.Integer(), default=TLPLevel.TLPAMBER)

    def __repr__(self):
        return 'Family %d %s' % (self.id, self.name)

    def __init__(self, name=None):
        if name is None:
            raise IOError
        self.name = name


class FamilySchema(ma.ModelSchema):
    """
    Schema for exporting by marshalling in JSON.
    """
    samples = fields.Nested(SampleSchema, many=True, only=['id'])
    subfamilies = fields.Nested('FamilySchema', many=True, only=['id',
                                                                 'name',
                                                                 'subfamilies',
                                                                 'status'])
    parents = fields.Nested('FamilySchema', many=True, only=['id', 'name'])
    users = fields.Nested('UserSchema', many=True, only=["id", "nickname"])

    class Meta(object):
        """
            List of simple fields
        """
        fields = ('id',
                  'name',
                  'parent_id',
                  'subfamilies',
                  'samples',
                  'abstract',
                  'status',
                  'TLP_sensibility',
                  'users')
