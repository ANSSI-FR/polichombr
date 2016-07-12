#!/usr/bin/env python
import sys
from poli import app

if len(sys.argv) > 1:
    app.config["SERVER_ADDR"] = sys.argv[1]
app.run(host=app.config["SERVER_ADDR"], port=app.config["SERVER_PORT"], debug=True)
