#!/usr/bin/env python
import sys
from time import sleep

from polichombr.controllers.api import APIControl
api = APIControl()

for i in sys.argv[1:]:
    api.analysiscontrol.schedule_sample_analysis(int(i), force=True)
    sleep(200)
