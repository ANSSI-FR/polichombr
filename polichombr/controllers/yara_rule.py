"""
    This file is part of Polichombr.

    (c) 2017 ANSSI-FR

    Description:
        Managers for editing and running yara rules
"""


import re
import yara

from sqlalchemy import or_

from polichombr import app, db

from polichombr.models.yara_rule import YaraRule
from polichombr.models.sample import Sample
from polichombr.models.models import TLPLevel
from polichombr.models.sample import FunctionInfo

from polichombr.controllers.jobpool import YaraJobPool
from polichombr.controllers.family import FamilyController


def run_simple_yara(raw_rule, sample):
    """
        Compile and run a yara rule on a given sample
    """
    matches = {}
    if sample.storage_file is None or sample.storage_file == "":
        return False
    sample_filepath = sample.storage_file

    try:
        yara_obj = yara.compile(source=raw_rule)
        matches = yara_obj.match(data=open(sample_filepath, "rb").read())
    except Exception as e:
        app.logger.exception("YARA RULE FAILED: %s" % (e))
    if matches:
        return True
    return False


def filter_funcs_infos(sid, hashes):
    """
        Return a query wich filters the func infos
        from a sample with given machoc hashes
    """
    filters = [int(m_hash[8:], 16) for m_hash in hashes]
    filters = FunctionInfo.machoc_hash.in_(filters)
    funcs = FunctionInfo.query.filter_by(sample_id=sid)
    funcs = funcs.filter(or_(filters))

    return funcs


def search_by_yara_regexp(raw_rule, sid, pattern):
    """
        Search for a pattern in the extended yara
        and return corresponding functions
    """
    matches = re.findall(pattern, raw_rule)
    if pattern:
        funcs = filter_funcs_infos(sid, matches)
    return funcs


def run_extended_yara(raw_rule, sample):
    '''

        Runs an extended Yara rule on a sample. It will just
        first parse the "machoc" keywords to pre-select matching
        samples, and then apply the yara rules.

        Machoc hashes must have been set in the sample, obviously.

    '''
    prematchs = search_by_yara_regexp(raw_rule,
                                      sample.id,
                                      "machoc==[0-9a-fA-F]{8}")
    if prematchs.count() == 0:
        return False

    noprematchs = search_by_yara_regexp(raw_rule,
                                        sample.id,
                                        "machoc!=[0-9a-fA-F]{8}")
    if noprematchs.count() > 0:
        return False

    return run_simple_yara(raw_rule, sample)


class YaraSingleTask(object):

    """
    Yara task. Used in the yara job pool. We use this task to
    define a yara rule which must be ran on a sample.
    """

    def __init__(self, sample, yar):
        self.yara_id = yar.id
        self.sample_id = sample.id
        self.matched = False

    def execute(self):
        """
        Get the objects, and run the extended yara.
        """
        with app.app_context():
            yar = YaraRule.query.get(self.yara_id)
            sample = Sample.query.get(self.sample_id)
            if yar in sample.yaras:
                return True
            if run_extended_yara(yar.raw_rule, sample) is True:
                self.matched = True
        return True

    def apply_result(self):
        """
        Commit the match in the sample.
        """
        if self.matched is False:
            return True
        yar = YaraRule.query.get(self.yara_id)
        sample = Sample.query.get(self.sample_id)
        if yar in sample.yaras:
            return True
        sample.yaras.append(yar)
        for family in yar.families:
            if family not in sample.families:
                sample.families.append(family)
        db.session.commit()
        return True


class YaraController(object):

    """
        Yara object controller.
    """

    jobpool = None

    def __init__(self):
        """
        Inits also the jobpool. Take care of it as it may spawn new processes.
        """
        self.jobpool = YaraJobPool()

    @staticmethod
    def get_all():
        """
        Get all yara rules.
        """
        return YaraRule.query.all()

    def execute_on_sample(self, sample, yar):
        """
        Execute rule on sample => add to the jobpool.
        """
        y_task = YaraSingleTask(sample, yar)
        self.jobpool.add_yara_task(y_task)
        return

    def create(self, name, raw_data, tlp_level):
        """
        Creates a new rule.
        Checks the rule before insertion, and executes it on
        any database sample.
        """
        if TLPLevel.tostring(tlp_level) is None:
            return False
        if YaraRule.query.filter_by(name=name).count() != 0:
            app.logger.error("This rule already exists")
            return False
        try:
            yara.compile(source=raw_data)
        except yara.SyntaxError as error:
            app.logger.error("Failed to compile rule %s", name)
            app.logger.exception(error)
            return False
        yar = YaraRule(name, raw_data, tlp_level)
        yar.version = 1
        db.session.add(yar)
        db.session.commit()
        for sample in Sample.query.all():
            self.execute_on_sample(sample, yar)
        return yar

    @staticmethod
    def get_by_id(yara_id):
        """
        Get yara rule by its ID.
        """
        return YaraRule.query.get(yara_id)

    @staticmethod
    def get_by_name(name):
        """
        Get yara rule by its name.
        """
        yar = YaraRule.query.filter_by(name=name)
        if yar is None:
            return None
        return yar.first()

    @staticmethod
    def add_to_item(item, yar):
        """
            Add a yara to a family or a sample
        """
        if yar in item.yaras:
            return True
        item.yaras.append(yar)
        return True

    @classmethod
    def add_to_sample(cls, sample, yar):
        """
        Adds yara to a sample. Checks before add. Commits also the yara's
        attached families.
        """
        cls.add_to_item(sample, yar)
        cls.propagate_family(sample, yar)
        db.session.commit()
        return True

    @staticmethod
    def propagate_family(sample, yar):
        """
            Dispatch families from a rule to a sample
        """
        for fam in yar.families:
            if fam not in sample.families:
                FamilyController.add_sample(sample, fam)

    @staticmethod
    def remove_from_family(fam, yar):
        """
        Removes yara to family.
        """
        if yar in fam.yaras:
            fam.yaras.remove(yar)
            db.session.commit()
        return True

    @classmethod
    def add_to_family(cls, fam, yar):
        """
        Adds a yara rule to a family. Also adds the samples. Sensibility
        is NOT propagated as a generic yara rule may be used to identify
        multiple families.
        """
        cls.add_to_item(fam, yar)
        for sample in yar.samples:
            cls.propagate_family(sample, yar)
        db.session.commit()
        return True

    @staticmethod
    def delete(yar):
        """
        Removes yara from database.
        """
        db.session.delete(yar)
        db.session.commit()
        return

    @staticmethod
    def rename(new_name, yar):
        """
        Change yara name.
        """
        yar.name = new_name
        db.session.commit()
        return True

    @staticmethod
    def update(rule, new_rule):
        """
            Update a rule with a new text.
            Also increments the version number
        """
        rule.raw_rule = new_rule
        rule.version += 1
        db.session.commit()
        return True

    @staticmethod
    def set_tlp_level(tlp_level, yar):
        """
        Change TLP level.
        """
        if TLPLevel.tostring(tlp_level) is None:
            return False
        yar.TLP_sensibility = tlp_level
        db.session.commit()
        return True
