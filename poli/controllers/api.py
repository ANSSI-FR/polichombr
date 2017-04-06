"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Main API controls for model management
        and data production.
"""


import zipfile
from StringIO import StringIO

from poli import app, db

from poli.models.models import TLPLevel
from poli.models.sample import AnalysisStatus
from poli.controllers.analysis import AnalysisController
from poli.controllers.sample import SampleController
from poli.controllers.yara_rule import YaraController
from poli.controllers.family import FamilyController
from poli.controllers.user import UserController
from poli.controllers.idaactions import IDAActionsController
from poli.models.sample import FunctionInfo


class APIControl(object):
    """
        Object used as a global API.
        Data controllers are used for direct data manipulation.
        Methods are used for complex (cross-data) manipulation.
            TODO: create a brand new analysis scheduler working on database
            samples status, and remove the analysis creation from this class.
    """

    familycontrol = None
    samplecontrol = None
    usercontrol = None
    analysiscontrol = None

    familycontrol = FamilyController()
    yaracontrol = YaraController()
    samplecontrol = SampleController()
    usercontrol = UserController()
    analysiscontrol = AnalysisController(
        app.config['ANALYSIS_PROCESS_POOL_SIZE'])
    idacontrol = IDAActionsController()

    def __init__(self):
        """
            Initiate controllers.
        """
        pass

    def dispatch_sample_creation(self,
                                 file_stream,
                                 filename="",
                                 user=None,
                                 tlp=TLPLevel.TLPWHITE,
                                 family=None):
        """
            If the sample is a ZipFile, we unpack it and return the last sample,
            otherwise we create a single sample and return it
        """
        file_data = file_stream.read(4)
        file_stream.seek(0)
        if file_data.startswith("PK"):
            samples = self.create_from_zip(file_stream, user, tlp, family)
        else:
            sample = self.create_sample_and_run_analysis(file_stream,
                                                         filename,
                                                         user,
                                                         tlp,
                                                         family)
            samples = [sample]
        return samples


    def create_from_zip(self, file_stream, user, tlp, family):
        """
            Iterates over the samples in the zip
        """
        output_samples = []
        file_data = StringIO(file_stream.read())
        with zipfile.ZipFile(file_data, "r") as zcl:
            for name in zcl.namelist():
                mfile = zcl.open(name, "r")
                sample = self.create_sample_and_run_analysis(mfile,
                                                             name,
                                                             user,
                                                             tlp,
                                                             family)
                output_samples.append(sample)
            zcl.close()
        return output_samples

    def create_sample_and_run_analysis(
            self,
            file_data_stream,
            originate_filename="",
            user=None,
            tlp_level=TLPLevel.TLPWHITE,
            family=None):
        """
            Creates a new sample and a schedule an analysis. We also check the
            file header for ZIP pattern: if a ZIP pattern is found, any file
            inside the archive will be imported and scheduled for analysis.

            TODO: move this to the SampleController, and start directly on new
            file submission.
        """
        file_data = file_data_stream.read()
        sample = self.samplecontrol.create_sample_from_file(
            file_data, originate_filename, user, tlp_level)
        if sample.analysis_status == AnalysisStatus.TOSTART:
            self.analysiscontrol.schedule_sample_analysis(sample.id)
        if family is not None:
            self.familycontrol.add_sample(sample, family)
        return sample

    def add_actions_fromfunc_infos(self, funcinfos, sample_dst, sample_src):
        """
            Create IDAActions from the samples's FuncInfos from AnalyzeIt
        """
        for fid_dst, fid_src in funcinfos:
            fsrc = FunctionInfo.query.get(fid_src)
            fdst = FunctionInfo.query.get(fid_dst)
            if fsrc is None or fdst is None:
                return False
            if fsrc not in sample_src.functions:
                return False
            if fdst not in sample_dst.functions:
                return False
            if fsrc.name.startswith("sub_"):
                continue
            act = self.idacontrol.add_name(int(fdst.address), fsrc.name)
            self.samplecontrol.add_idaaction(sample_dst.id, act)
        db.session.commit()
        return True
