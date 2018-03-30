"""
    This file is part of Polichombr
        (c) 2016 ANSSI-FR
    Published without any garantee under CeCill v2 license.

    This file is used to make a count of machoc hashes.
    It can help to discover outliers (for example, empty blocks),
    and to establish a blacklist of machoc hashes.
"""

from polichombr.models.sample import FunctionInfo
from sqlalchemy import desc, func
from polichombr import db
from pprint import pprint

functions = db.session.query(FunctionInfo.machoc_hash, func.count(1).label("count"))
functions = functions.group_by(FunctionInfo.machoc_hash).order_by(desc("count"))
functions = functions.limit(100).all()

for f in functions:
    pprint("0x%x : %d" % (f[0], f[1]))
