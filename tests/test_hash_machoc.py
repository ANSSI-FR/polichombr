#!/usr/bin/env python

from app.controllers import api
from app.models.sample import Sample
import sys


if len(sys.argv) > 1:
    sid = sys.argv[1]
    result = api.get_machoc_matches(sid)
    print result
else:

    count = len(Sample.query.all())

    for i,s  in enumerate(Sample.query.all()):
        result = api.get_machoc_matches(s.id)
        if result != -1 :
            pass
            #print result
        print i, " / ", count 
