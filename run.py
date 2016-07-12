#!/usr/bin/env python
from poli import app

if __name__ == "__main__":
    app.run(app.config['SERVER_ADDR'],
            port=app.config['SERVER_PORT'],
            debug=app.config['DEBUG'])
