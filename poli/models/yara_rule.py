"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Yara rules model representation.
"""

from datetime import datetime

from poli import db, ma


class YaraRule(db.Model):
    """
        Yara rule model.
    """
    __tablename__ = 'yararule'
    id = db.Column(db.Integer, primary_key=True)
    # yara name (displayed)
    name = db.Column(db.String(), unique=True)
    # raw yara rule
    raw_rule = db.Column(db.String())
    # creation's date
    creation_date = db.Column(db.DateTime())
    # TLP sensibility
    TLP_sensibility = db.Column(db.Integer(), nullable=False)

    def __init__(self, name, raw_rule, tlp_level):
        self.creation_date = datetime.now()
        self.modif_date = datetime.now()
        self.raw_rule = raw_rule
        self.name = name
        self.TLP_sensibility = tlp_level


class YaraSchema(ma.ModelSchema):
    class Meta(object):
        fields = ('id',
                  'name',
                  'raw_rule',
                  'creation_date',
                  'TLP_sensibility')
