"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        peinfo task implementation
"""

import datetime
import time
import pefile

from poli import app
from poli.models.sample import SampleMetadataType
from poli.controllers.task import Task
from poli.controllers.sample import SampleController


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
        self.metadata_extracted.append((
            SampleMetadataType.PE_import_hash,
            self.import_hash))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_magic,
            pe.DOS_HEADER.e_magic))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_cblp,
            pe.DOS_HEADER.e_cblp))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_cp,
            pe.DOS_HEADER.e_cp))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_crlc,
            pe.DOS_HEADER.e_crlc))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_cparhdr,
            pe.DOS_HEADER.e_cparhdr))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_minalloc,
            pe.DOS_HEADER.e_minalloc))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_maxalloc,
            pe.DOS_HEADER.e_maxalloc))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_ss,
            pe.DOS_HEADER.e_ss))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_sp,
            pe.DOS_HEADER.e_sp))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_csum,
            pe.DOS_HEADER.e_csum))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_ip,
            pe.DOS_HEADER.e_ip))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_cs,
            pe.DOS_HEADER.e_cs))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_lfarlc,
            pe.DOS_HEADER.e_lfarlc))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_ovno,
            pe.DOS_HEADER.e_ovno))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_res,
            pe.DOS_HEADER.e_res))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_oemid,
            pe.DOS_HEADER.e_oemid))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_oeminfo,
            pe.DOS_HEADER.e_oeminfo))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_res2,
            pe.DOS_HEADER.e_res2))
        self.metadata_extracted.append((
            SampleMetadataType.PE_DOS_HEADER_e_lfanew,
            pe.DOS_HEADER.e_lfanew))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_Machine,
            pe.FILE_HEADER.Machine))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_NumberOfSections,
            pe.FILE_HEADER.NumberOfSections))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_TimeDateStamp,
            pe.FILE_HEADER.TimeDateStamp))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_PointerToSymbolTable,
            pe.FILE_HEADER.PointerToSymbolTable))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_NumberOfSymbols,
            pe.FILE_HEADER.NumberOfSymbols))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_SizeOfOptionalHeader,
            pe.FILE_HEADER.SizeOfOptionalHeader))
        self.metadata_extracted.append((
            SampleMetadataType.PE_FILE_HEADER_Characteristics,
            pe.FILE_HEADER.Characteristics))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_Magic,
            pe.OPTIONAL_HEADER.Magic))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorLinkerVersion,
            pe.OPTIONAL_HEADER.MajorLinkerVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorLinkerVersion,
            pe.OPTIONAL_HEADER.MinorLinkerVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfCode))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfInitializedData))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_BaseOfCode,
            pe.OPTIONAL_HEADER.BaseOfCode))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_ImageBase,
            pe.OPTIONAL_HEADER.ImageBase))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SectionAlignment,
            pe.OPTIONAL_HEADER.SectionAlignment))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_FileAlignment,
            pe.OPTIONAL_HEADER.FileAlignment))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorOperatingSystemVersion,
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorImageVersion,
            pe.OPTIONAL_HEADER.MajorImageVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorImageVersion,
            pe.OPTIONAL_HEADER.MinorImageVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MajorSubsystemVersion,
            pe.OPTIONAL_HEADER.MajorSubsystemVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_MinorSubsystemVersion,
            pe.OPTIONAL_HEADER.MinorSubsystemVersion))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_Reserved1,
            pe.OPTIONAL_HEADER.Reserved1))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfImage,
            pe.OPTIONAL_HEADER.SizeOfImage))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeaders,
            pe.OPTIONAL_HEADER.SizeOfHeaders))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_CheckSum,
            pe.OPTIONAL_HEADER.CheckSum))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_Subsystem,
            pe.OPTIONAL_HEADER.Subsystem))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_DllCharacteristics,
            pe.OPTIONAL_HEADER.DllCharacteristics))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfStackReserve,
            pe.OPTIONAL_HEADER.SizeOfStackReserve))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfStackCommit,
            pe.OPTIONAL_HEADER.SizeOfStackCommit))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeapReserve,
            pe.OPTIONAL_HEADER.SizeOfHeapReserve))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_SizeOfHeapCommit,
            pe.OPTIONAL_HEADER.SizeOfHeapCommit))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_LoaderFlags,
            pe.OPTIONAL_HEADER.LoaderFlags))
        self.metadata_extracted.append((
            SampleMetadataType.PE_OPTIONAL_HEADER_NumberOfRvaAndSizes,
            pe.OPTIONAL_HEADER.NumberOfRvaAndSizes))
        return True

    def apply_result(self):
        s_controller = SampleController()
        sample = s_controller.get_by_id(self.sid)
        app.logger.debug(self.tmessage + "APPLY_RESULT")
        # Compilation timestamp (even when faked) IS a file date, so update it.
        s_controller.add_multiple_metadata(sample, self.metadata_extracted)
        s_controller.set_file_date(sample, self.compile_timestamp)
        s_controller.set_import_hash(sample, self.import_hash)
        app.logger.debug(self.tmessage + "END - TIME %i" %
                         (int(time.time()) - self.tstart))
        return True
