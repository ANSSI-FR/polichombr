"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Models to implement IDA Pro objects server side.
"""

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
        'polymorphic_identity': 'analysisresult',
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


class IDAStructs():
    pass


class IDAActionSchema(ma.ModelSchema):

    class Meta:
        fields = (
            "timestamp",
            "address",
            "data",
            "type"
        )
