#!/usr/bin/env python
from poli import app
from poli import db
from poli.models.models import User
from poli.models.family import Family
from poli.models.sample import Sample

Sample.query.delete()
Family.query.delete()
User.query.delete()
db.session.commit()
