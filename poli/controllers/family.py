"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Implement the controller managing families.
"""


import os
import time
import tarfile

from hashlib import md5, sha256

from poli import app
from poli import db
from poli.models.family import FamilySchema, FamilyStatus
from poli.models.family import Family, DetectionElement, FamilyDataFile
from poli.models.family import DetectionType
from poli.models.models import TLPLevel


class FamilyController(object):
    """
        Family object controller.
    """

    def __init__(self):
        pass

    @staticmethod
    def create(name, parentfamily=None):
        """
            @arg name: family name
            @arg parentfamily: parent family
            @arg return None if incorrect arg, family object if created|exists
        """
        if Family.query.filter_by(name=name).count() != 0:
            return Family.query.filter_by(name=name).first()
        family = Family(name)
        db.session.add(family)
        if parentfamily is not None:
            parentfamily.subfamilies.append(family)
            family.TLP_sensibility = parentfamily.TLP_sensibility
        db.session.commit()
        return family

    @staticmethod
    def get_by_id(fid):
        """
            Gets by ID.
        """
        return Family.query.get(fid)

    @staticmethod
    def get_by_name(name):
        """
            Gets by name.
        """
        family = Family.query.filter_by(name=name).first()
        if family is None:
            return None
        return family

    @staticmethod
    def get_users_for_family(family):
        """
            Gets family users, which worked on its samples.

            TODO: direct SQL request?
        """
        users = []
        for sample in family.samples:
            for user in sample.users:
                if user not in users:
                    users.append(user)
        return users

    def get_all_schema(self):
        """
            Schema export.
        """
        fschema = FamilySchema(many=True)
        families = self.get_all()
        return {'families': fschema.dump(families).data}

    @staticmethod
    def get_all():
        """
            Get all the families.
        """
        return Family.query.all()

    @staticmethod
    def add_sample(sample, family, no_propagation=False):
        """
            Adds a new sample to the family. Propagate TLP sensibility.
        """
        if sample in family.samples:
            return True
        family.samples.append(sample)
        if not no_propagation:
            if sample.TLP_sensibility < family.TLP_sensibility:
                sample.TLP_sensibility = family.TLP_sensibility
        db.session.commit()
        return True

    @staticmethod
    def remove_sample(sample, family):
        """
            Remove a sample from the family.
        """
        if sample in family.samples:
            family.samples.remove(sample)
            db.session.commit()
        return True

    @staticmethod
    def remove_user(user, family):
        """
            Remove a user from the family.
        """
        if user in family.users:
            family.users.remove(user)
            db.session.commit()
        return True

    @staticmethod
    def add_user(user, family):
        """
            Add a user to the family.
        """
        if user in family.users:
            return True
        family.users.append(user)
        db.session.commit()
        return True

    @staticmethod
    def set_status(family, status):
        """
            Change analysis status.
        """
        if FamilyStatus.tostring(status) == "":
            return False
        family.status = status
        db.session.commit()
        return True

    @staticmethod
    def set_abstract(family, abstract):
        """
            Change analysis abstract.
        """
        family.abstract = abstract
        db.session.commit()
        return True

    def delete(self, family):
        """
            Delete family. Recursively.
        """
        for subfamily in family.subfamilies:
            self.delete(subfamily)
        for associated_file in family.associated_files:
            db.session.delete(associated_file)
        for detection_item in family.detection_items:
            db.session.delete(detection_item)
        db.session.delete(family)
        db.session.commit()
        return True

    def set_tlp_level(self, family, tlp_level, no_propagation=False):
        """
            Change TLP level. Propagates to other items.
        """
        if family.parents:
            if family.parents.TLP_sensibility > tlp_level:
                return False
        family.TLP_sensibility = tlp_level
        if not no_propagation:
            dependencies = [family.samples, family.associated_file,
                            family.detection_items]
            for dependency in dependencies:
                for item in dependency:
                    if item.TLP_sensibility < tlp_level:
                        item.TLP_sensibility = tlp_level
            for subfamily in family.subfamilies:
                if subfamily.TLP_sensibility < tlp_level:
                    self.set_tlp_level(subfamily, tlp_level, no_propagation)
        db.session.commit()
        return True

    @staticmethod
    def generate_samples_zip_file(family, tlp_level):
        """
            Generates a sample ZIP file.
            We actually store it in the storage under a
            unique filename : family-tlp_level-sha256(samples sha256).
            By doing this we may avoid losing time generating already
            generated files.
        """
        if TLPLevel.tostring(int(tlp_level)) == "":
            return None
        zipname = ""
        for sample in family.samples:
            if sample.TLP_sensibility <= tlp_level:
                zipname += sample.sha256
        zip_fname = family.name + "-" + \
            str(tlp_level) + "-" + sha256(zipname).hexdigest()
        zip_fname += ".tar.gz"

        zip_path = os.path.join(app.config['STORAGE_PATH'], zip_fname)
        if os.path.exists(zip_path):
            return zip_path

        tarf = tarfile.open(zip_path, "w:gz")
        for x in family.samples:
            if x.TLP_sensibility <= tlp_level:
                if os.path.exists(x.storage_file):
                    tarf.add(x.storage_file, arcname=x.sha256)
        tarf.close()
        return zip_path

    @staticmethod
    def export_yara_ruleset(family, tlp_level):
        """
            Exports the yara rules.
        """
        generated_output = "/* Polichombr ruleset export */\n/* Family: " + \
            family.name + " */\n\n"
        for yar in family.yaras:
            if yar.TLP_sensibility <= tlp_level:
                generated_output += "/* Internal name: " + yar.name + " */\n"
                generated_output += "/* TLP level: " + \
                    TLPLevel.tostring(yar.TLP_sensibility) + " */\n"
                generated_output += "/* Creation date: " + \
                    str(yar.creation_date) + " */\n"
                generated_output += yar.raw_rule + "\n\n"
        return generated_output

    @staticmethod
    def export_detection_openioc(family, tlp_level):
        """
            Exports the detection OPENIOC items.

            TODO: move openioc generation to a new file.
        """
        generated_output = "<?xml version=\"1.0\" encoding=\"us-ascii\"?>\n"
        for item in family.detection_items:
            if item.TLP_sensibility <= tlp_level:
                if item.item_type == DetectionType.OPENIOC:
                    generated_output += '<ioc xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="polichombr-' + \
                        str(family.id) + '-' + str(item.id) + '">\n'
                    generated_output += '<short_description>' + family.name + \
                        ' custom IOC #' + str(item.id) + \
                        '</short_description>\n'
                    generated_output += '<description>Cutom IOC for ' + \
                        family.name + ' samples family</description>\n'
                    generated_output += '<tlp_sensibility>' + \
                        TLPLevel.tostring(
                            item.TLP_sensibility) + '</tlp_sensibility>'
                    generated_output += '<authored_date>Polichombr</authored_date>\n'
                    generated_output += '<links />\n'
                    generated_output += '<definition>\n'
                    generated_output += item.abstract + '\n'
                    generated_output += '</definition>\n</ioc>\n\n\n'
        generated_output += "</ioc>"
        return generated_output

    @staticmethod
    def export_detection_snort(family, tlp_level):
        """
            Exports the yara detection SNORT rules.
        """
        generated_output = "# SNORT ruleset for family " + family.name + "\n\n"
        for item in family.detection_items:
            if item.TLP_sensibility <= tlp_level:
                if item.item_type == DetectionType.SNORT:
                    generated_output += "# rule internal name: " + item.name + "\n"
                    generated_output += "# rule TLP sensibility: " + \
                        TLPLevel.tostring(item.TLP_sensibility) + "\n"
                    generated_output += item.abstract + "\n\n"
        return generated_output

    @staticmethod
    def export_detection_custom(family, tlp_level):
        """
            Exports the yara detection CUSTOM items.
        """
        generated_output = "Custom detection items for family " + family.name + "\n\n"
        for item in family.detection_items:
            if item.TLP_sensibility <= tlp_level:
                if item.item_type == DetectionType.CUSTOM:
                    generated_output += "Name: " + item.name + "\n"
                    generated_output += "TLP sensibility: " + \
                        TLPLevel.tostring(item.TLP_sensibility) + "\n"
                    generated_output += "Content:\n" + item.abstract + "\n\n"
        return generated_output

    @staticmethod
    def export_samplesioc(family, tlp_level):
        """
            Exports the family's samples OPENIONC (auto-generated).

            TODO: I'm pretty sure this code can be cleaned...
        """
        generated_output = "<?xml version=\"1.0\" encoding=\"us-ascii\"?>\n"
        generated_output += '<ioc xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="polichombr-' + \
            str(family.id) + '-autogen">\n'
        generated_output += '<short_description>' + family.name + \
            ' auto-generated</short_description>\n'
        generated_output += '<description>Auto-generated IOC for ' + \
            family.name + ' samples family</description>\n'
        generated_output += '<authored_date>Polichombr</authored_date>\n'
        generated_output += '<links />\n'
        generated_output += '<definition>\n'
        generated_output += '<Indicator operator="OR" id="1">\n'
        c = 2
        for sample in family.samples:
            if sample.TLP_sensibility <= tlp_level:
                generated_output += '<IndicatorItem id="' + \
                    str(c) + '" condition="is">\n'
                generated_output += '<Context document="FileItem" search="FileItem/Md5sum" type="mir" />\n'
                generated_output += '<Content type="md5">' + sample.md5 + '</Content>\n'
                generated_output += '<Context document="FileItem" search="FileItem/Sha1sum" type="mir" />\n'
                generated_output += '<Content type="sha1">' + sample.sha1 + '</Content>\n'
                generated_output += '<Context document="FileItem" search="FileItem/Sha256sum" type="mir" />\n'
                generated_output += '<Content type="sha256">' + sample.sha256 + '</Content>\n'
                generated_output += '</IndicatorItem>\n'
                c = c + 1
        generated_output += '</Indicator>\n'
        generated_output += '</definition>\n'
        generated_output += '</ioc>'
        return generated_output

    @staticmethod
    def add_file(filedata, filename, description, tlp_level, family):
        """
            Creates an attached file.
        """
        if TLPLevel.tostring(tlp_level) is None:
            return False
        storage_file_name = md5(str(int(time.time()))).hexdigest() + ".bin"
        stored_path = os.path.join(
            app.config['STORAGE_PATH'],
            storage_file_name)
        open(stored_path, 'wb').write(filedata)
        x = FamilyDataFile()
        x.filepath = stored_path
        x.filename = filename
        x.description = description
        x.TLP_sensibility = tlp_level
        family.associated_files.append(x)
        db.session.add(x)
        db.session.commit()
        return True

    @staticmethod
    def delete_file(datafile):
        """
            Deletes an attached file.
        """
        if os.path.exists(datafile.filepath):
            os.remove(datafile.filepath)
        db.session.delete(datafile)
        return True

    @staticmethod
    def get_file_by_id(file_id):
        """
            Gets an attached file.
        """
        return FamilyDataFile.query.get(file_id)

    @staticmethod
    def get_detection_item_by_id(item_id):
        """
            Gets a detection item.
        """
        return DetectionElement.query.get(item_id)

    @staticmethod
    def delete_detection_item(item):
        """
            Deletes a detection item.
        """
        db.session.delete(item)
        db.session.commit()
        return True

    @staticmethod
    def create_detection_item(abstract, name, tlp_level, item_type, family):
        """
            Creates a detection item.
        """
        if DetectionType.tostring(item_type) == "":
            return False
        if TLPLevel.tostring(tlp_level) is None:
            return False
        if family.TLP_sensibility > tlp_level:
            tlp_level = family.TLP_sensibility

        item = DetectionElement()
        item.abstract = abstract
        item.name = name
        item.TLP_sensibility = tlp_level
        item.item_type = item_type

        family.detection_items.append(item)
        db.session.add(item)
        db.session.commit()
        return True
