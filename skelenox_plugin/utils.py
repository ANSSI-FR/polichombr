"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Contains various utility functions for interacting
        with IDA database
"""

import logging

import idc
import idaapi
import ida_bytes
import ida_name

logger = logging.getLogger(__name__)


class SkelUtils(object):
    """
        Utils functions
    """

    @staticmethod
    def prepare_parse_type(typestr, addr):
        """
            idc.ParseType doesnt accept types without func / local name
            as exported by default GetType
            this is an ugly hack to fix it
        """
        lname = idc.get_name(addr)
        if lname is None:
            lname = "Default"

        # func pointers
        conventions = ["__cdecl *",
                       "__stdcall *",
                       "__fastcall *",
                       # "__usercall *",
                       # "__userpurge *",
                       "__thiscall *",
                       "__cdecl",
                       "__stdcall",
                       "__fastcall",
                       # "__usercall",
                       # "__userpurge",
                       "__thiscall"]

        mtype = None
        for conv in conventions:
            if conv in typestr:
                mtype = typestr.replace(conv, conv + " " + lname)
                break
        return mtype

    @staticmethod
    def header():
        """
            help!
        """
        print("-*" * 40)
        print("                 SKELENOX ")
        print("        This plugin is part of Polichombr")
        print("             (c) ANSSI-FR 2018")
        print("-" * 80)
        print("\t Collaborative reverse engineering framework")
        print("Help:")
        print("see   https://www.github.com/anssi-fr/polichombr/docs/")
        print("-*" * 40)
        print("\tfile %IDB%_backup_preskel contains IDB backup before running")
        print("\tfile %IDB%_backup_ contains periodic IDB backups")
        return

    @staticmethod
    def filter_coms_blacklist(cmt):
        """
            These are standards coms, we don't want them in the DB
        """
        if cmt is None:
            logger.error("No comment provided to filter_coms")
            return True
        black_list = [
            "size_t", "int", "LPSTR", "char", "char *", "lpString",
            "dw", "lp", "Str", "Dest", "Src", "cch", "Dst", "jumptable",
            "switch ", "unsigned int", "void *", "Size",
            "indirect table for switch statement", "this", "jump table for",
            "switch jump", "nSize", "hInternet", "hObject",
            "SEH", "Exception handler", "Source", "Size", "Val", "Time",
            "struct", "unsigned __int", "__int32", "void (", "Memory",
            "HINSTANCE", "jumptable"
        ]
        for elem in black_list:
            if cmt.lower().startswith(elem.lower()):
                logger.debug("Comment %s has been blacklisted", cmt)
                return True
        return False

    @staticmethod
    def execute_comment(comment):
        """
            Thread safe comment wrapper
        """
        def make_rpt():
            """
                Inserting a comment
            """
            ida_bytes.set_cmt(
                comment["address"],
                comment["data"].encode(
                    'ascii',
                    'replace'),
                1)
        cmt = idc.get_cmt(comment["address"], 0)
        if cmt != comment["data"] and idc.get_cmt(
                comment["address"], 1) != comment["data"]:
            logger.debug(
                "[x] Adding comment %s @ 0x%x ",
                comment["data"],
                comment["address"])
            return idaapi.execute_sync(make_rpt, idaapi.MFF_FAST)
        return None

    @staticmethod
    def execute_rename(name):
        """
            This is a wrapper to execute the renaming synchronously
        """
        def get_name():
            return idc.get_name(name["address"])

        def make_name(force=False):
            """
                Thread safe renaming wrapper
            """
            def sync_ask_rename():
                """
                    Dialog asking renaming confirmation to the user
                """
                rename_flag = 0
                if force or idc.ask_yn(rename_flag, "Replace %s by %s" %
                                       (get_name(), name["data"])) == 1:
                    logger.debug("[x] renaming %s @ 0x%x as %s",
                                 get_name(),
                                 name["address"],
                                 name["data"])
                    ida_name.set_name(
                        name["address"], name["data"].encode(
                            'ascii', 'ignore'),
                        ida_name.SN_AUTO)
            return idaapi.execute_sync(
                sync_ask_rename,
                idaapi.MFF_FAST)
        old_name = get_name()
        if not name["data"]:
            return
        elif idaapi.has_dummy_name(idaapi.get_flags(name["address"])) or not old_name:
            make_name(force=True)
        elif get_name() != name["data"]:
            make_name()

    @staticmethod
    def get_comment(address):
        """
            Wrapper to get both the Cmt and RptCmt
        """
        cmt_types = [idc.get_cmt, idc.get_func_cmt]  # TODO: RPT CMT
        calculated_cmt = ""
        for cmt_type in cmt_types:
            cmt = None
            cmt = cmt_type(address, 0)
            if cmt and not SkelUtils.filter_coms_blacklist(cmt):
                if cmt not in calculated_cmt:
                    calculated_cmt += cmt
        return calculated_cmt
