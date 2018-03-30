# This file is part of Polichombr.
# Copyright 2014 - 2016 Tristan Pourcelot <tristan.pourcelot@ssi.gouv.fr>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.)
FROM debian:jessie

MAINTAINER Tristan Pourcelot <tristan.pourcelot@ssi.gouv.fr>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get upgrade -qq
RUN apt-get dist-upgrade -qq

RUN apt-get install -qqy git virtualenv ruby libffi-dev python-dev graphviz gcc libssl-dev

ADD https://github.com/anssi-fr/polichombr/tarball/master poli.tar.gz

RUN mv poli.tar.gz /opt/ && cd /opt/ && \
	tar xzf poli.tar.gz && mv ANSSI-FR-polichombr-* polichombr && \
	cd polichombr && \
	./install.sh
WORKDIR /opt/polichombr

RUN sed -i '/SQLALCHEMY_DATABASE_URI/c\SQLALCHEMY_DATABASE_URI = "sqlite:////opt/data/app.db"' config.py
RUN sed -i '/STORAGE_PATH/c\STORAGE_PATH = "/opt/data/storage"' config.py

ADD https://github.com/jjyg/metasm/tarball/master metasm.tar.gz
RUN tar xzf metasm.tar.gz && mv jjyg-metasm-*/* metasm && rm metasm.tar.gz

VOLUME "/opt/data/"
RUN mv examples/db_create.py db_create.py

EXPOSE 5000
CMD flask/bin/python db_create.py && flask/bin/python run.py
