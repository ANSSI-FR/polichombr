"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        peinfo task implementation
"""

import datetime
import time
import pefile

from polichombr import app
from polichombr.models.sample import SampleMetadataType
from polichombr.controllers.task import Task
from polichombr.controllers.sample import SampleController


class task_peinfo(Task):

    """
    Extract basic metadata from pefile.

    TODO: also extract Exports, Imports and Sections.
    """

    def __init__(self, sample):
        super(task_peinfo, self).__init__()
        self.sid = sample.id
        self.compile_timestamp = None
        self.import_hash = ""
        self.matches = []
        self.metadata_extracted = []
        self.fpath = sample.storage_file

        self.tstart = None
        self.tmessage = "PEINFO TASK %d :: " % (sample.id)

        # ignore non-PE files
        if "application/x-dosexec" not in sample.mime_type:
            self.is_interrested = False
        return

    def execute(self):
        self.tstart = int(time.time())
        app.logger.debug(self.tmessage + "EXECUTE")
        pe = pefile.PE(self.fpath)
        self.compile_timestamp = datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp)
        self.import_hash = pe.get_imphash()

        metadata = self.generate_metadata(pe)

        self.metadata_extracted.append((
            SampleMetadataType.PE_import_hash,
            self.import_hash))

        for item in metadata.items:
            self.metadata_extracted.append(item)

        return True

    def apply_result(self):
        s_controller = SampleController()
        with app.app_context():
            sample = s_controller.get_by_id(self.sid)
            app.logger.debug(self.tmessage + "APPLY_RESULT")
            s_controller.add_multiple_metadata(sample, self.metadata_extracted)

            # Compilation timestamp IS a file date, so update it.
            s_controller.set_file_date(sample, self.compile_timestamp)
            s_controller.set_import_hash(sample, self.import_hash)
        app.logger.debug(self.tmessage + "END - TIME %i" %
                         (int(time.time()) - self.tstart))
        return True

    @staticmethod
    def generate_metadata(pe):
        pe_metadata = {
            SampleMetadataType.PE_DOS_HEADER_e_magic: pe.DOS_HEADER.e_magic,
            SampleMetadataType.PE_DOS_HEADER_e_cblp: pe.DOS_HEADER.e_cblp,
            SampleMetadataType.PE_DOS_HEADER_e_cp: pe.DOS_HEADER.e_cp,
            SampleMetadataType.PE_DOS_HEADER_e_crlc: pe.DOS_HEADER.e_crlc,
            SampleMetadataType.PE_DOS_HEADER_e_cparhdr: pe.DOS_HEADER.e_cparhdr,
            SampleMetadataType.PE_DOS_HEADER_e_minalloc: pe.DOS_HEADER.e_minalloc,
            SampleMetadataType.PE_DOS_HEADER_e_maxalloc: pe.DOS_HEADER.e_maxalloc,
            SampleMetadataType.PE_DOS_HEADER_e_ss: pe.DOS_HEADER.e_ss,
            SampleMetadataType.PE_DOS_HEADER_e_sp: pe.DOS_HEADER.e_sp,
            SampleMetadataType.PE_DOS_HEADER_e_csum: pe.DOS_HEADER.e_csum,
            SampleMetadataType.PE_DOS_HEADER_e_ip: pe.DOS_HEADER.e_ip,
            SampleMetadataType.PE_DOS_HEADER_e_cs: pe.DOS_HEADER.e_cs,
            SampleMetadataType.PE_DOS_HEADER_e_lfarlc: pe.DOS_HEADER.e_lfarlc,
            SampleMetadataType.PE_DOS_HEADER_e_ovno: pe.DOS_HEADER.e_ovno,
            SampleMetadataType.PE_DOS_HEADER_e_res: pe.DOS_HEADER.e_res,
            SampleMetadataType.PE_DOS_HEADER_e_oemid: pe.DOS_HEADER.e_oemid,
            SampleMetadataType.PE_DOS_HEADER_e_oeminfo: pe.DOS_HEADER.e_oeminfo,
            SampleMetadataType.PE_DOS_HEADER_e_res2: pe.DOS_HEADER.e_res2,
            SampleMetadataType.PE_DOS_HEADER_e_lfanew: pe.DOS_HEADER.e_lfanew,
            SampleMetadataType.PE_FILE_HEADER_Machine: pe.FILE_HEADER.Machine,
            SampleMetadataType.PE_FILE_HEADER_NumberOfSections: pe.FILE_HEADER.NumberOfSections,
            SampleMetadataType.PE_FILE_HEADER_TimeDateStamp: pe.FILE_HEADER.TimeDateStamp,
            SampleMetadataType.PE_FILE_HEADER_PointerToSymbolTable: pe.FILE_HEADER.PointerToSymbolTable,
            SampleMetadataType.PE_FILE_HEADER_NumberOfSymbols: pe.FILE_HEADER.NumberOfSymbols,
            SampleMetadataType.PE_FILE_HEADER_SizeOfOptionalHeader: pe.FILE_HEADER.SizeOfOptionalHeader,
            SampleMetadataType.PE_FILE_HEADER_Characteristics: pe.FILE_HEADER.Characteristics,
            SampleMetadataType.PE_OPTIONAL_HEADER_Magic: pe.OPTIONAL_HEADER.Magic,
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorLinkerVersion: pe.OPTIONAL_HEADER.MajorLinkerVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorLinkerVersion: pe.OPTIONAL_HEADER.MinorLinkerVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfCode: pe.OPTIONAL_HEADER.SizeOfCode,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfInitializedData: pe.OPTIONAL_HEADER.SizeOfInitializedData,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfUninitializedData: pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            SampleMetadataType.PE_OPTIONAL_HEADER_AddressOfEntryPoint: pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            SampleMetadataType.PE_OPTIONAL_HEADER_BaseOfCode: pe.OPTIONAL_HEADER.BaseOfCode,
            SampleMetadataType.PE_OPTIONAL_HEADER_ImageBase: pe.OPTIONAL_HEADER.ImageBase,
            SampleMetadataType.PE_OPTIONAL_HEADER_SectionAlignment: pe.OPTIONAL_HEADER.SectionAlignment,
            SampleMetadataType.PE_OPTIONAL_HEADER_FileAlignment: pe.OPTIONAL_HEADER.FileAlignment,
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorOperatingSystemVersion: pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorOperatingSystemVersion: pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorImageVersion: pe.OPTIONAL_HEADER.MajorImageVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorImageVersion: pe.OPTIONAL_HEADER.MinorImageVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorSubsystemVersion: pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorSubsystemVersion: pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            SampleMetadataType.PE_OPTIONAL_HEADER_Reserved1: pe.OPTIONAL_HEADER.Reserved1,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfImage: pe.OPTIONAL_HEADER.SizeOfImage,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeaders: pe.OPTIONAL_HEADER.SizeOfHeaders,
            SampleMetadataType.PE_OPTIONAL_HEADER_CheckSum: pe.OPTIONAL_HEADER.CheckSum,
            SampleMetadataType.PE_OPTIONAL_HEADER_Subsystem: pe.OPTIONAL_HEADER.Subsystem,
            SampleMetadataType.PE_OPTIONAL_HEADER_DllCharacteristics: pe.OPTIONAL_HEADER.DllCharacteristics,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfStackReserve: pe.OPTIONAL_HEADER.SizeOfStackReserve,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfStackCommit: pe.OPTIONAL_HEADER.SizeOfStackCommit,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeapReserve: pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeapCommit: pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            SampleMetadataType.PE_OPTIONAL_HEADER_LoaderFlags: pe.OPTIONAL_HEADER.LoaderFlags,
            SampleMetadataType.PE_OPTIONAL_HEADER_NumberOfRvaAndSizes: pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }
        return pe_metadata
