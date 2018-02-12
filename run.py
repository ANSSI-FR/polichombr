#!/usr/bin/env python
"""
    This file is part of Polichombr.

    (c) 2018 ANSSI-FR


    Description:
        Wrapper for running the application
"""

from poli import app

if __name__ == "__main__":

    app.run(app.config['SERVER_ADDR'],
            port=app.config['SERVER_PORT'],
            debug=app.config['DEBUG'])
