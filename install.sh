#!/bin/bash

#Prerequisites, on a ubuntu* distribution.
sudo apt-get install -y git virtualenv ruby libffi-dev python-dev graphviz gcc libssl-dev python-pip
git submodule init metasm # or clone github.com/jjyg/metasm
git submodule update metasm

virtualenv flask
source flask/bin/activate
pip install future
pip install flask flask-login flask-sqlalchemy flask-wtf flask-bootstrap
pip install sqlalchemy-migrate
pip install flask-marshmallow marshmallow-sqlalchemy # marshalling for the API
pip install python-magic
pip install requests
pip install pefile
pip install markdown
pip install Flask-Misaka
pip install Flask-Testing
pip install graphviz
pip install yara-python

export PYTHONPATH=`pwd`:$PYTHONPATH
./utils/db_create.py

#./run.py
