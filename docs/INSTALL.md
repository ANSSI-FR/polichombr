# Installation
## Prerequisites

Polichombr is based on the `Flask` framework and this needs several dependencies to be installed.

To install them on an Ubuntu derivative:
	sudo apt-get install -y git virtualenv ruby libffi-dev python-dev graphviz gcc libssl-dev python-pip

## Initialization
        ./install.sh
        ./utils/db_create.py

## Get it up and running
        ./run.py

Access it at http://localhost:5000

## Production ready version: using nginx and uwsgi
The previous version uses the ``flask`` debug server, and thus is not suitable for production use.

The preferred configuration is using `nginx` to dispatch request to an `uwsgi` broker.

The `uwsgi` server can be configured by modifying the `poli.ini` file according to your needs,
and telling `nginx` to forward request to `uwsgi`.

Then to launch the app:

	uwsgi --ini poli.ini

Now access it at the defined address for your nginx server!

## virtualenv
A Python virtual environment is created by the installer script, so don't forget to activate it

        source flask/bin/activate

## Alternative: postgresql
The polichombr DB backends also supports PostgreSQL, but it relies on some specific dependencies

```
	sudo apt-get install libpq-dev postgresql-server-dev-all
	pip install psycopg2
```

Replace the DB url in the `config.py` file by the one corresponding to you DB configuration.
