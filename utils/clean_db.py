#!/usr/bin/env python
from app import app
from app import db
from app.models.models import User
from app.models.family import Family
from app.models.sample import Sample

Sample.query.delete()
Family.query.delete()
User.query.delete()
db.session.commit()
