#!/usr/bin/env python
"""
    Managers for editing and running yara rules
"""

import re
import yara

from app import db

from app.models.yara_rule import YaraRule
from app.models.sample import Sample
from app.models.models import TLPLevel

from app.controllers.jobpool import YaraJobPool
from app.controllers.family import FamilyController


def run_extended_yara(raw_rule, sample):
    '''

        Runs an extended Yara rule on a sample. It will just
        first parse the "machoc" keywords to pre-select matching
        samples, and then apply the yara rules.

        Machoc hashes must have been set in the sample, obviously.

    '''
    matches = {}
    if sample.storage_file is None or sample.storage_file == "":
        return False
    sample_filepath = sample.storage_file
    machoc_prematchs = re.findall("machoc==[0-9a-fA-F]{8}", raw_rule)
    machoc_noprematchs = re.findall("machoc!=[0-9a-fA-F]{8}", raw_rule)
    if len(machoc_noprematchs) != 0:
        for m_hash in machoc_noprematchs:
            for s_function in sample.functions:
                if s_function.machoc_hash == m_hash[8:]:
                    return False
    if len(machoc_prematchs) != 0:
        for m_hash in machoc_prematchs:
            flag = 1
            for s_function in sample.functions:
                if s_function.machoc_hash == m_hash[8:]:
                    flag = 0
                    break
            if flag == 1:
                return False
    try:
        yara_obj = yara.compile(source=raw_rule)
        matches = yara_obj.match(data=open(sample_filepath, "rb").read())
    except Exception as e:
        app.logger.error("YARA RULE FAILED: %s" % (e))
        pass
    if len(matches) != 0:
        return True
    return False


class YaraSingleTask:
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
        for f in yar.families:
            if f not in sample.families:
                sample.families.append(f)
        db.session.commit()
        return True


class YaraController(object):

    """
        Yara object controller.
        TODO: rename methods.
    """

    jobpool = None

    def __init__(self):
        """
        Inits also the jobpool. Take care of it as it may spawn new processes.
        """
        self.jobpool = YaraJobPool()

    def get_all(self):
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
        Creates a new rule. Checks the rule before insertion, and executes it on
        any database sample.
        """
        if TLPLevel.tostring(tlp_level) is None:
            return False
        if YaraRule.query.filter_by(name=name).count() != 0:
            return None
        try:
            yara.compile(source=raw_data)
        except Exception as e:
            app.logger.exception(e)
            return None
        yar = YaraRule(name, raw_data, tlp_level)
        db.session.add(yar)
        db.session.commit()
        for s in Sample.query.all():
            self.execute_on_sample(s, yar)
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
    def add_to_sample(sample, yar):
        """
        Adds yara to a sample. Checks before add. Commits also the yara's
        attached families.
        """
        if yar in sample.yaras:
            return True
        sample.yaras.append(yar)
        for fam in yar.families:
            if fam not in sample.families:
                FamilyController().add_sample(sample, fam)
        db.session.commit()
        return True

    @staticmethod
    def remove_to_family(fam, yar):
        """
        Removes yara to family.
        """
        if yar in fam.yaras:
            fam.yaras.remove(yar)
            db.session.commit()
        return True

    @staticmethod
    def add_to_family(fam, yar):
        """
        Adds a yara rule to a family. Also adds the samples. Sensibility
        is NOT propagated as a generic yara rule may be used to identify
        multiple families.
        """
        if yar in fam.yaras:
            return True
        fam.yaras.append(yar)
        for sample in yar.samples:
            if fam not in sample.families:
                FamilyController().add_sample(sample, fam)
        db.session.commit()
        return

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
    def set_tlp_level(tlp_level, yar):
        """
        Change TLP level.
        """
        if TLPLevel.tostring(tlp_level) is None:
            return False
        yar.TLP_sensibility = tlp_level
        db.session.commit()
        return True
