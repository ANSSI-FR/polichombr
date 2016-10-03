#!/usr/bin/env python

from app.controllers.api import APIControl
from app.models.sample import Sample
from app.models.analysis import IDACommentAction, IDANameAction
import datetime
import requests


api = APIControl()

api.idacontrol.add_comment(1, 0x12345, 'This is a test')


print api.idacontrol.get_comments(1)

data = {"timestamp": str(datetime.datetime.now()),
        "addr": 0x12345,
        "comment": "This is a comment test"
        }
r = requests.post("http://localhost:5000/api/1.0/samples/" +
                  '1' +
                  '/ida/comments',
                  json=data)

s = Sample.query.get(1)

toto = IDANameAction()
titi = IDACommentAction()
toto.address = 0xDEADBEEF
titi.address = 0x0BADCAFE

toto.data = "This is a name"
titi.data = "This is a comment"
toto.timestamp = datetime.datetime.now()
titi.timestamp = datetime.datetime.now()

api.db_add_commit_element(toto)
api.db_add_commit_element(titi)

s.actions.append(toto)
s.actions.append(titi)
api.db_add_commit_element(s)


s = Sample.query.get(1)

for a in s.actions:
    print a.id,
    print a.type,
    print a.timestamp,
    print hex(a.address),
    print a.data

