"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Implements the hooks needed for accessing IDA's information
"""

import logging

import idaapi
import ida_idp
import ida_typeinf
import idc

from .utils import SkelUtils

logger = logging.getLogger(__name__)


class SkelIDBHook(ida_idp.IDB_Hooks):
    """
        IDB hooks, subclassed from ida_idp.py
    """
    skel_conn = None

    def __init__(self, skel_conn):
        ida_idp.IDB_Hooks.__init__(self)
        self.skel_conn = skel_conn

    def area_cmt_changed(self, *args):
        """
            Function comments are Area comments
        """
        cb, area, cmt, rpt = args
        self.skel_conn.push_comment(area.startEA, cmt)

        return ida_idp.IDB_Hooks.area_cmt_changed(self, *args)

    def renamed(self, *args):
        logger.debug("[IDB Hook] Something is renamed")
        ea, new_name, is_local_name = args
        min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
        max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
        if ea >= min_ea and ea <= max_ea:
            if is_local_name:
                logger.warning("Local names are unimplemented")
            else:
                auto = idaapi.has_auto_name(idaapi.get_flags(ea))
                dummy = idaapi.has_dummy_name(idaapi.get_flags(ea))
                if not dummy and not auto:
                    self.skel_conn.push_name(ea, new_name)
        else:
            logger.warning("ea outside program...")

        return ida_idp.IDB_Hooks.renamed(self, *args)

    def cmt_changed(self, *args):
        """
            A comment changed somewhere
        """
        addr, rpt = args
        logger.debug("Changed cmt at 0x%x rpt is %d",
                     addr, rpt)
        cmt = idc.get_cmt(addr, rpt)
        if not SkelUtils.filter_coms_blacklist(cmt):
            self.skel_conn.push_comment(addr, cmt)
        return ida_idp.IDB_Hooks.cmt_changed(self, *args)

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

        return ida_idp.IDB_Hooks.struc_created(self, *args)

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
        mname = idaapi.get_member_name(mptr.id)

        self.skel_conn.create_struct_member(struct_id,
                                            mname,
                                            m_start_offset)

        return ida_idp.IDB_Hooks.struc_member_created(self, *args)

    def deleting_struc(self, *args):
        """
        deleting_struc(self, sptr) -> int
        """
        sptr, = args
        name = idaapi.get_struc_name(sptr.id)
        struc_id = self.skel_conn.get_struct_by_name(name)
        self.skel_conn.delete_struct(struc_id)
        return ida_idp.IDB_Hooks.deleting_struc(self, *args)

    def renaming_struc(self, *args):
        """
        renaming_struc(self, id, oldname, newname) -> int
        """
        sid, oldname, newname = args
        logger.debug("Renaming struc %d %s to %s",
                     sid, oldname, newname)
        struct_id = self.skel_conn.get_struct_by_name(oldname)
        self.skel_conn.rename_struct(struct_id, newname)
        return ida_idp.IDB_Hooks.renaming_struc(self, *args)

    def expanding_struc(self, *args):
        """
        expanding_struc(self, sptr, offset, delta) -> int
        """
        return ida_idp.IDB_Hooks.expanding_struc(self, *args)

    def changing_struc_cmt(self, *args):
        """
        changing_struc_cmt(self, struc_id, repeatable, newcmt) -> int
        """
        return ida_idp.IDB_Hooks.changing_struc_cmt(self, *args)

    def deleting_struc_member(self, *args):
        """
        deleting_struc_member(self, sptr, mptr) -> int
        """
        return ida_idp.IDB_Hooks.deleting_struc_member(self, *args)

    def renaming_struc_member(self, *args):
        """
        renaming_struc_member(self, sptr, mptr, newname) -> int
        """
        sptr, mptr, newname = args
        logger.debug("Renaming struct member %s of struct %s",
                     mptr.id, sptr.id)
        sname = idaapi.get_struc_name(sptr.id)
        oldname = idaapi.get_member_name(mptr.id)
        struct_id = self.skel_conn.get_struct_by_name(sname)
        mid = self.skel_conn.get_member_by_name(struct_id, oldname)
        self.skel_conn.rename_struct_member(struct_id, mid, newname)

        return ida_idp.IDB_Hooks.renaming_struc_member(self, *args)

    def changing_struc(self, *args):
        """
            changing_struc(self, sptr) -> int
        """
        sptr, = args
        logger.debug("Changing structure %s",
                     idaapi.get_struc_name(sptr.id))
        return ida_idp.IDB_Hooks.changing_struc(args)

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
        return ida_idp.IDB_Hooks.changing_struc_member(self, *args)

    def op_type_changed(self, *args):
        ea, n = args
        logger.debug("Type changed at 0x%x type 0x%x", ea, n)
        return ida_idp.IDB_Hooks.op_type_changed(self, *args)

    def func_added(self, *args):
        pfn = args
        logger.debug("New function added at 0x%x", pfn)
        return ida_idp.IDB_Hooks.func_added(self, *args)

    def make_code(self, *args):
        insn = args[0]
        logger.debug("Make code called")
        logger.debug(insn)
        return ida_idp.IDB_Hooks.make_code(self, *args)

    def make_data(self, *args):
        ea, flags, tid, length = args
        logger.debug("New data at 0x%x, length 0x%x, flags 0x%x ",
                     ea,
                     length,
                     flags)
        return ida_idp.IDB_Hooks.make_data(self, *args)

    def op_ti_changed(self, *args):
        self, ea, ftype, fnames = args
        logger.debug("TI Changed at 0x%x type %s fnames 0x%s",
                     ea,
                     ftype,
                     fnames)
        return ida_idp.IDB_Hooks.op_ti_changed(self, *args)

    def ti_changed(self, *args):
        ea, ftype, fnames = args
        new_type = ida_typeinf.print_type(ea, 0)
        logger.debug("New type 0x%x : %s", ea, new_type)
        self.skel_conn.push_type(ea, new_type)
        return ida_idp.IDB_Hooks.ti_changed(self, *args)


class SkelHooks(object):
    """
        Class containing the different hooks for skelenox

        SkelIDBHook:
            * Catches the main actions
            Drawbacks:
                - type info management
                - doesn't catch naming actions
    """
    idb_hook = None

    def __init__(self, skel_conn):
        self.idb_hook = SkelIDBHook(skel_conn)

    def hook(self):
        self.idb_hook.hook()

    def cleanup_hooks(self):
        """
            Clean IDA hooks on exit
        """
        if self.idb_hook is not None:
            self.idb_hook.unhook()
            self.idb_hook = None
        return
