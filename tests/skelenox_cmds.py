"""
    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Semi automated test that add some data in the IDA database,
        that should be reflected in the second database
"""


import ida_name, ida_bytes, ida_struct
import idc

ida_name.set_name(0x401000, "TESTFUNCTION")
ida_bytes.set_cmt(0x40100A, "TEST COMMENT", 0)
ida_bytes.set_cmt(0x40100F, "TEST RPT COMMENT", 1)

struct_1 = ida_struct.add_struc(0, "TESTSTRUCT1")

struct_pointer = ida_struct.get_struc(struct_1)

ida_struct.add_struc_member(struct_pointer, "TESTMEMBER", 0, 0, None, 0)

idc.SetType(0x401000, "int __cdecl start(char *lpszTestArg);")
