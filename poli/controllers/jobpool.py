"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Implement analysis job pools.
"""

import atexit
from multiprocessing import Pool, Queue

from poli import app, db


def execute_task(mqueue):
    """
    Simple worker wich will execute the tasks analyses. It ends on setting the
    analysis status as finished.
    """
    while True:
        m_analysis = mqueue.get(True)
        if m_analysis is None:
            return False
        m_analysis.tasks.sort()
        for level, mtask in m_analysis.tasks:
            # TRY/CATCH block to avoid blocking tasks
            try:
                result = mtask.execute()
                if result:
                    mtask.apply_result()
                if not result:
                    app.logger.error("Error executing task %s" % (mtask))
            except Exception as e:
                app.logger.error("Error executing task %s (%s)" % (mtask, e))
                app.logger.exception(e)
                db.session.rollback()
                continue
            del mtask
        m_analysis.set_finished()
    return True


def execute_yara_task(mqueue):
    """
    Special dedicated YARA worker. Dispatches newly created yara rules on the
    samples pool. There is no analysis in this case,
    nor priority considerations, that's why it has been separated.
    """
    while True:
        yara_task = mqueue.get(True)
        if yara_task is None:
            return False
        try:
            result = yara_task.execute()
            if result:
                result = yara_task.apply_result()
            if not result:
                app.logger.error("Error executing yara task %s" % (yara_task))
        except Exception as e:
            db.session.rollback()
            app.logger.error("Exception executing yara task: %s" % (e))
            app.logger.exception(e)
            continue
    return True


class JobPool(object):
    """
    Pool container.
    """
    pool = None
    message_queue = None

    def __init__(self, max_instances=4):
        self.message_queue = Queue()
        self.pool = Pool(max_instances, execute_task, (self.message_queue,))
        atexit.register(self.clear)

    def add_analysis(self, analysis):
        """
        Add analysis to the pool.
        """
        analysis.set_started()
        self.message_queue.put(analysis)

    def clear(self):
        """
        Pool cleanup.
        """
        self.pool.terminate()
        self.pool.join()


class YaraJobPool(object):
    """
    Yara pool container.
    """
    pool = None
    message_queue = None

    def __init__(self, max_instances=3):
        self.message_queue = Queue()
        self.pool = Pool(max_instances, execute_yara_task,
                         (self.message_queue,))
        atexit.register(self.clear)

    def add_yara_task(self, yara_task):
        """
        Adds the yara task.
        """
        self.message_queue.put(yara_task)

    def clear(self):
        """
        Pool cleanup.
        """
        self.pool.terminate()
        self.pool.join()
