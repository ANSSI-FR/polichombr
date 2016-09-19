"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Models to implement IDA Pro objects server side.
"""

from marshmallow import fields

from poli import db, ma


class IDAAction(db.Model):
    """
        Abstract class for implementing IDA actions.
        This mirrors actions done by the analyst on his database
    """
    __tablename__ = "idaactions"
    id = db.Column(db.Integer(), primary_key=True)

    # The action data
    data = db.Column(db.String())

    # The address where the action occured
    address = db.Column(db.Integer(), index=True)

    # We must keep timestamp to reorder actions
    timestamp = db.Column(db.DateTime())

    # We also keep the last user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # The action type
    type = db.Column(db.String())
    __mapper_args__ = {
        'polymorphic_identity': 'idaactions',
        'polymorphic_on': type
    }


class IDACommentAction(IDAAction):
    """
        Implement comments
    """
    __tablename__ = 'idacomments'
    id = db.Column(db.Integer(),
                   db.ForeignKey('idaactions.id'),
                   primary_key=True)
    comment = db.Column(db.String())
    __mapper_args__ = {
        'polymorphic_identity': 'idacomment'}


class IDANameAction(IDAAction):
    __tablename__ = 'idanames'
    id = db.Column(db.Integer(),
                   db.ForeignKey('idaactions.id'),
                   primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity': 'idanames'}


class IDAApplyStructs(IDAAction):
    __tablename__ = 'idaapplystructs'
    id = db.Column(db.Integer(),
                   db.ForeignKey('idaactions.id'),
                   primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity': 'idaapplystructs'}


class IDAStruct(IDAAction):
    """
        Structures are a particular type of
        actions, as the address and will always be null,
        and they store a relationship with their members
        The management of the members is done by the controller,
        and at each update the structure's timestamp is updated
    """
    __tablename__ = "idastructs"
    id = db.Column(db.Integer(),
                   db.ForeignKey('idaactions.id'),
                   primary_key=True)
    name = db.Column(db.String())
    size = db.Column(db.Integer())
    members = db.relationship("IDAStructMember",
            backref=db.backref("struct"),
            remote_side=[id])


    __mapper_args__ = {
        "polymorphic_identity": "idastructs"}


class IDAStructMember(db.Model):
    __tablename__ = "idastructmember"
    id = db.Column(db.Integer(), primary_key=True)
    struct_id = db.Column(db.Integer(), db.ForeignKey("idastructs.id"))
    name = db.Column(db.String())
    size = db.Column(db.Integer())
    mtype = db.Column(db.String())
    offset = db.Column(db.Integer())


class IDAActionSchema(ma.ModelSchema):

    class Meta:
        fields = (
            "timestamp",
            "address",
            "data",
            "type",
        )

class IDAStructMemberSchema(ma.ModelSchema):
    class Meta:
        fields=(
            "id",
            "name",
            "offset",
            "size",
            "mtype"
        )

class IDAStructSchema(ma.ModelSchema):
    members = fields.Nested('IDAStructMemberSchema',
                            only=['id', 'name', 'offset', 'size', 'mtype'],
                            many=True)
    class Meta:
        fields = (
                "id",
                "timestamp",
                "name",
                "size",
                "members"
        )
