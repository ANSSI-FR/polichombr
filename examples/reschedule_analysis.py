#!/usr/bin/env python

from time import sleep

from poli import app
from poli.controllers.api import APIControl


def launch():
    api = APIControl()
    api.analysiscontrol.reschedule_all_analysis(True)
    app.logger.info("Rescheduled all analysis!")
    sleep(2000000)
    return 0

if __name__ == "__main__":
    launch()
