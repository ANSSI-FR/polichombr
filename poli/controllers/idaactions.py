"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Managers for all the actions associated with IDAPro models
"""

import datetime

from poli import db
from poli.models.idaactions import IDANameAction, IDACommentAction
from poli.models.idaactions import IDAActionSchema
from poli.models.idaactions import IDAStruct, IDAStructSchema
from poli.models.idaactions import IDAStructMember, IDAStructSchema
from poli.models.sample import Sample


class IDAActionsController(object):
    """
        Manage the recorded actions for IDA Pro.
    """

    @staticmethod
    def add_comment(address, data):
        """
            Creates a new comment action
        """
        comment = IDACommentAction()
        comment.address = address
        comment.data = data
        comment.timestamp = datetime.datetime.now()
        db.session.add(comment)
        db.session.commit()
        return comment.id

    @staticmethod
    def get_comments(sid=None, addr=None, timestamp=None):
        """
            Filters for getting comments
            @arg addr Is there a comment for a specific address
            @timestamp Get only after this timestamp
        """
        if timestamp is None:
            timestamp = 0
        # first query
        comments = IDACommentAction.query
        comments = comments.filter(
            IDACommentAction.samples.any(Sample.id == sid))
        comments = comments.filter(timestamp >= timestamp)
        if addr is not None:
            comments = comments.filter_by(address=addr).all()
        else:
            comments = comments.all()
        schema = IDAActionSchema(many=True)
        data = schema.dump(comments).data
        return data

    @staticmethod
    def add_name(address=None, data=None):
        """
            Creates a new name action
        """
        name = IDANameAction()
        name.address = address
        name.data = data
        name.timestamp = datetime.datetime.now()
        db.session.add(name)
        db.session.commit()
        return name.id

    @staticmethod
    def get_names(sid, addr=None, timestamp=None):
        """
            Return defined names for a specific sample
            @arg addr the address for a specific name
            @timestamp Last syncho timestamp
        """
        query = IDANameAction.query
        query = query.filter(IDANameAction.samples.any(Sample.id == sid))
        if addr is not None:
            query = query.filter_by(addr=addr)

        if timestamp is not None:
            query = query.filter_by(timestamp >= timestamp)

        data = query.all()
        schema = IDAActionSchema(many=True)
        return schema.dump(data).data

    @staticmethod
    def create_struct(name=None):
        if name is None:
            app.logger.error("Cannot create anonymous struct")
            return False
        mstruct = IDAStruct()
        mstruct.name = name
        mstruct.timestamp = datetime.datetime.now()
        mstruct.size = 0
        db.session.add(mstruct)
        db.session.commit()
        return mstruct.id

    @staticmethod
    def get_structs(sid, timestamp=None):
        query = IDAStruct.query
        query = query.filter(IDAStruct.samples.any(Sample.id == sid))

        if timestamp is not None:
            query = query.filter_by(timestamp >= timestamp)

        data = query.all()
        schema = IDAStructSchema(many=True)
        return schema.dump(data).data

    @staticmethod
    def get_one_struct(sid, struct_id):
        """
            Get only one structure
        """
        query = IDAStruct.query
        data = query.get(struct_id)

        schema = IDAStructSchema()
        return schema.dump(data).data


    @staticmethod
    def create_struct_member(name=None, size=None, offset=None):
        member = IDAStructMember()
        if member is None:
            return False
        member.name = name
        member.size = size
        member.offset = offset
        db.session.add(member)
        db.session.commit()
        return member.id

    @staticmethod
    def add_member_to_struct(struct_id=None, mid=None, offset=None):
        """

        """
        struct = IDAStruct.query.get(struct_id)
        member = IDAStructMember.query.get(mid)
        if struct is None or member is None:
            result = False
        else:
            struct.members.append(member)
            # struct is updated, so we must update the timestamp
            struct.timestamp = datetime.datetime.now()
            if member.offset >= struct.size:
                struct.size += (member.offset - struct.size)
            struct.size += member.size
            db.session.commit()
            result = True
        return result

    @staticmethod
    def change_struct_member_name(struct_id, mid, new_name):
        struct = IDAStruct.query.get(struct_id)
        member = None
        if struct is None:
            return False
        for m in struct.members:
            if m.id == mid:
                member = m
                break
        if member is None:
            return False
        member.name = new_name
        struct.timestamp = datetime.datetime.now()
        db.session.commit()
        return True

    @staticmethod
    def change_struct_member_size(struct_id, mid, new_size):
        struct = IDAStruct.query.get(struct_id)
        member = None
        if struct is None:
            return False
        for m in struct.members:
            if m.id == mid:
                member = m
                break
        if member is None:
            return False

        if member.offset + member.size == struct.size:
            struct.size = struct.size - (member.size - new_size)
        member.size = new_size

        struct.timestamp = datetime.datetime.now()
        db.session.commit()

        return True
