# Installation
## Prerequisites
On a Ubuntu derivative:
        ``sudo apt-get install -y git virtualenv ruby libffi-dev python-dev graphviz gcc libssl-dev python-pip``

## Initialization
        ./install.sh
        ./utils/db_create.py

## Get it up and running
        ./run.py

Access it at http://localhost:5000

## With nginx and uwsgi
Configure your nginx to use the uwsgi protocol, and modify the `poli.ini`
file according to your needs.

Then  launch the app:
	uwsgi --ini poli.ini

Now access it at the defined address for nginx

## virtualenv
We use virtualenv, so don't forget to activate the environment

        source flask/bin/activate

## Alternative: postgresql
The polichombr backends also supports
PostgreSQL

```
	sudo apt-get install libpq-dev postgresql-server-dev-all
	pip install psycopg2
```

Replace the DB url in the `config.py` file by the one corresponding to you DB configuration.
