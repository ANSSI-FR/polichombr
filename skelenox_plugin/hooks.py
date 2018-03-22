"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Implements the hooks needed for accessing IDA's information
"""

import logging

import idaapi
import idc

from .utils import SkelUtils

logger = logging.getLogger(__name__)


class SkelHooks(object):
    """
        Class containing the three different hooks for skelenox

        SkelUIHook :
            * Original UI hook, catch cmds.
            Drawbacks : doesn't catch the actions made by scripts

        SkelIDBHook:
            * Catches the main actions
            Drawbacks:
                - type info management
                - doesn't catch naming actions
        SkelIDPHook:
            * IDPHook used for the actions not implemented in IDBHooks

    """
    ui_hook = None
    idb_hook = None
    idp_hook = None

    class SkelUIHook(idaapi.UI_Hooks):
        """
            Catch IDA UI actions and send them
        """
        cmdname = ""
        addr = 0
        skel_conn = None

        def __init__(self, skel_conn):
            idaapi.UI_Hooks.__init__(self)
            self.skel_conn = skel_conn

        def preprocess(self, name):
            self.cmdname = name
            self.addr = idc.here()
            return 0

        def postprocess(self):
            try:
                if self.cmdname == "MakeFunction":
                    if idc.GetFunctionAttr(self.addr, 0) is not None:
                        # Push "MakeFunction" change
                        pass
                elif self.cmdname == "DeclareStructVar":
                    logger.error("Fixme : declare Struct variable")
                elif self.cmdname == "SetType":
                    newtype = idc.GetType(self.addr)
                    if newtype is None:
                        newtype = ""
                    else:
                        newtype = SkelUtils.prepare_parse_type(
                            newtype, self.addr)
                        self.skel_conn.push_type(int(self.addr), newtype)
                elif self.cmdname == "OpStructOffset":
                    logger.debug("A struct member is typed to struct offset")
            except KeyError:
                logger.debug("Got unimplemented ops %s", self.cmdname)
            return 0

    class SkelIDBHook(idaapi.IDB_Hooks):
        """
            IDB hooks, subclassed from ida_idp.py
        """
        skel_conn = None

        def __init__(self, skel_conn):
            idaapi.IDB_Hooks.__init__(self)
            self.skel_conn = skel_conn

        def area_cmt_changed(self, *args):
            """
                Function comments are Area comments
            """
            cb, area, cmt, rpt = args
            self.skel_conn.push_comment(area.startEA, cmt)

            return idaapi.IDB_Hooks.area_cmt_changed(self, *args)

        def renamed(self, *args):
            logger.debug("[IDB Hook] Something is renamed")
            ea, new_name, is_local_name = args
            if ea >= idc.MinEA() and ea <= idc.MaxEA():
                if is_local_name:
                    logger.warning("Local names are unimplemented")
                else:
                    auto = idaapi.has_auto_name(idaapi.get_flags(ea))
                    dummy = idaapi.has_dummy_name(idaapi.get_flags(ea))
                    if not dummy and not auto:
                        self.skel_conn.push_name(ea, new_name)
            else:
                logger.warning("ea outside program...")

            return idaapi.IDB_Hooks.renamed(self, *args)

        def cmt_changed(self, *args):
            """
                A comment changed somewhere
            """
            addr, rpt = args
            if rpt:
                cmt = idc.RptCmt(addr)
            else:
                cmt = idc.Comment(addr)
            if not SkelUtils.filter_coms_blacklist(cmt):
                self.skel_conn.push_comment(addr, cmt)
            return idaapi.IDB_Hooks.cmt_changed(self, *args)

        def changing_cmt(self, *args):
            ea, rpt, newcmt = args
            logger.debug("Changing cmt at 0x%x for '%s' rpt is %d",
                         ea, newcmt, rpt)
            return idaapi.IDB_Hooks.changing_cmt(self, *args)

        def gen_regvar_def(self, *args):
            v = args
            logger.debug(dir(v))
            logger.debug(vars(v))

        def struc_created(self, *args):
            """
                args -> id
            """
            struct_name = idaapi.get_struc_name(args[0])
            self.skel_conn.create_struct(struct_name)

            logger.debug("New structure %s created", struct_name)

            return idaapi.IDB_Hooks.struc_created(self, *args)

        def struc_member_created(self, *args):
            """
                struc_member_created(self, sptr, mptr) -> int
            """
            sptr, mptr = args
            logger.debug("New member for structure %s",
                         idaapi.get_struc_name(sptr.id))

            m_start_offset = mptr.soff
            # logger.debug("Member start offset 0x%x", m_start_offset)
            # logger.debug("Member end offset 0x%x", m_end_offset)
            struct_name = idaapi.get_struc_name(sptr.id)
            struct_id = self.skel_conn.get_struct_by_name(struct_name)
            mname = idaapi.get_member_name2(mptr.id)

            self.skel_conn.create_struct_member(struct_id,
                                                mname,
                                                m_start_offset)

            return idaapi.IDB_Hooks.struc_member_created(self, *args)

        def deleting_struc(self, *args):
            """
            deleting_struc(self, sptr) -> int
            """
            sptr, = args
            name = idaapi.get_struc_name(sptr.id)
            struc_id = self.skel_conn.get_struct_by_name(name)
            self.skel_conn.delete_struct(struc_id)
            return idaapi.IDB_Hooks.deleting_struc(self, *args)

        def renaming_struc(self, *args):
            """
            renaming_struc(self, id, oldname, newname) -> int
            """
            sid, oldname, newname = args
            logger.debug("Renaming struc %d %s to %s",
                         sid, oldname, newname)
            struct_id = self.skel_conn.get_struct_by_name(oldname)
            self.skel_conn.rename_struct(struct_id, newname)
            return idaapi.IDB_Hooks.renaming_struc(self, *args)

        def expanding_struc(self, *args):
            """
            expanding_struc(self, sptr, offset, delta) -> int
            """
            return idaapi.IDB_Hooks.expanding_struc(self, *args)

        def changing_struc_cmt(self, *args):
            """
            changing_struc_cmt(self, struc_id, repeatable, newcmt) -> int
            """
            return idaapi.IDB_Hooks.changing_struc_cmt(self, *args)

        def deleting_struc_member(self, *args):
            """
            deleting_struc_member(self, sptr, mptr) -> int
            """
            return idaapi.IDB_Hooks.deleting_struc_member(self, *args)

        def renaming_struc_member(self, *args):
            """
            renaming_struc_member(self, sptr, mptr, newname) -> int
            """
            sptr, mptr, newname = args
            logger.debug("Renaming struct member %s of struct %s",
                         mptr.id, sptr.id)
            sname = idaapi.get_struc_name(sptr.id)
            oldname = idaapi.get_member_name2(mptr.id)
            struct_id = self.skel_conn.get_struct_by_name(sname)
            mid = self.skel_conn.get_member_by_name(struct_id, oldname)
            self.skel_conn.rename_struct_member(struct_id, mid, newname)

            return idaapi.IDB_Hooks.renaming_struc_member(self, *args)

        def changing_struc(self, *args):
            """
                changing_struc(self, sptr) -> int
            """
            sptr, = args
            logger.debug("Changing structure %s",
                         idaapi.get_struc_name(sptr.id))
            return idaapi.IDB_Hooks.changing_struc(args)

        def changing_struc_member(self, *args):
            """
            changing_struc_member(self, sptr, mptr, flag, ti, nbytes) -> int
            """
            logger.debug("Changing struct member")
            mystruct, mymember, flag, ti, nbytes = args
            # print ti
            # print dir(ti)
            # print ti.cd
            # print ti.ec
            # print ti.ri
            # print ti.tid
            return idaapi.IDB_Hooks.changing_struc_member(self, *args)

        def op_type_changed(self, *args):
            return idaapi.IDB_Hooks.op_type_changed(self, *args)

    class SkelIDPHook(idaapi.IDP_Hooks):
        """
            IDP hook
        """
        skel_conn = None

        def __init__(self, skel_conn):
            idaapi.IDP_Hooks.__init__(self)
            self.skel_conn = skel_conn

        def renamed(self, *args):
            logger.debug("[IDP Hook] Something is renamed")
            ea, new_name, is_local_name = args
            if ea >= idc.MinEA() and ea <= idc.MaxEA():
                if is_local_name:
                    logger.warning("Local names are unimplemented")
                    pass
                else:
                    auto = idaapi.has_auto_name(idaapi.get_flags(ea))
                    dummy = idaapi.has_dummy_name(idaapi.get_flags(ea))
                    if not dummy and not auto:
                        self.skel_conn.push_name(ea, new_name)
            else:
                logger.warning("ea outside program...")

            return idaapi.IDP_Hooks.renamed(self, *args)

    def __init__(self, skel_conn):
        self.ui_hook = SkelHooks.SkelUIHook(skel_conn)
        self.idb_hook = SkelHooks.SkelIDBHook(skel_conn)
        self.idp_hook = SkelHooks.SkelIDPHook(skel_conn)

    def hook(self):
        self.ui_hook.hook()
        self.idb_hook.hook()
        self.idp_hook.hook()

    def cleanup_hooks(self):
        """
            Clean IDA hooks on exit
        """
        if self.ui_hook is not None:
            self.ui_hook.unhook()
            self.ui_hook = None

        if self.idb_hook is not None:
            self.idb_hook.unhook()
            self.idb_hook = None

        if self.idp_hook is not None:
            self.idp_hook.unhook()
            self.idp_hook = None
        return
