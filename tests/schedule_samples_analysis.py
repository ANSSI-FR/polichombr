#!/usr/bin/env python
import sys
from time import sleep

from app.controllers.api import APIControl
api = APIControl()

for i in sys.argv[1:]:
    api.analysiscontrol.schedule_sample_analysis(int(i))
    sleep(200)
