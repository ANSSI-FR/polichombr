## Sample submissions
You can submit samples from the web interface,
or using the script provided in ``tests/send_sample.py``


## Users management
The first user is automatically an administrator.
Further users registration will need to be activated by an administrator.

## The latest update did break my install, what to do?
When new models are added (as in polichombr#29 for example ),
the database needs to be upgraded with the following command:

  `python utils/db_migrate.py`
