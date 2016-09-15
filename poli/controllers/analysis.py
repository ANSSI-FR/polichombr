"""
    This file is part of Polichombr.

    (c) 2016 ANSSI-FR


    Description:
        Analysis management
"""

import os
import re
import importlib
import inspect

from poli import app, db
from poli.models.sample import Sample, AnalysisStatus
from poli.controllers.jobpool import JobPool


class AnalysisFactory(object):
    """
        Dynamically loads tasks from directory
    """
    tasks_classes_container = None

    def __init__(self):
        self.tasks_classes_container = []
        self.load_tasks()

    def load_tasks(self):
        """
        Dynamically loads the tasks in the tasks/ folder. The tasks must
        be loaded here in order to avoid too much memory usage.
        """
        app.logger.info("Loading tasks")
        srcre = re.compile('.py$', re.IGNORECASE)
        tasks_files = filter(srcre.search,
                             os.listdir(app.config['TASKS_PATH']))
        form_module = lambda fp: os.path.splitext(fp)[0]
        tasks_modules = map(form_module, tasks_files)
        for task_filename in tasks_modules:
            if not task_filename.startswith('__'):
                try:
                    package_name = app.config['TASKS_PATH'].replace("/", ".")
                    task_module = importlib.import_module(
                        "." + task_filename, package=package_name)
                    for task_name, task_class in inspect.getmembers(
                            task_module):
                        if task_name == task_filename and inspect.isclass(
                                task_class):
                            self.tasks_classes_container.append(
                                (task_class, task_filename))
                            app.logger.info("Imported task %s" % (task_filename))
                except Exception as e:
                    app.logger.error(
                        "Could not load %s : %s" %
                        (task_filename, e))
                    continue
        return True

    def create_analysis(self, sample):
        """
        Creates a simple analysis from a sample.
        """
        analysis = Analysis(sample)
        if analysis is None:
            app.logger.error("The factory couldn't generate an analysis...")
            return None
        self.assign_tasks(analysis, sample)
        return analysis

    def assign_tasks(self, analysis, sample):
        """
        Creates tasks, and, if they will run on the sample, add them to the
        analysis.
        """
        for p_class, p_name in self.tasks_classes_container:
            try:
                p_instance = p_class(sample)
                if p_instance.will_run():
                    analysis.add_task(p_instance, p_name)
            except Exception as e:
                app.logger.error("Could not load task %s : %s" % (p_name, e))
                app.logger.exception(e)
                pass
        return True


class AnalysisController(object):
    """
    Manages the creation, dispatch and management of analysis tasks
    """
    jobpool = None
    factory = None

    def __init__(self, max_instances=4):
        self.jobpool = JobPool(max_instances)
        self.factory = AnalysisFactory()

    def create_analysis(self, sid, force=False):
        """
        Creates an analysis for SID sample. If force, will create the analysis
        even if the analysis status is FINISHED or RUNNING.
        """
        sample = Sample.query.get(sid)
        if sample is None:
            return None
        if sample.analysis_status == AnalysisStatus.RUNNING and not force:
            return None
        if sample.analysis_status == AnalysisStatus.FINISHED and not force:
            return None
        return self.factory.create_analysis(sample)

    def dispatch_analysis(self, analysis):
        """
        Send the analysis to the job queue.
        """
        if analysis.tasks is None or len(analysis.tasks) == 0:
            return False
        self.jobpool.add_analysis(analysis)
        return True

    def schedule_sample_analysis(self, sid, force=False):
        """
        Create analysis, and dispatch it to execution pool.
        """
        analysis = self.create_analysis(sid, force)
        if analysis is None:
            app.logger.error("No analysis generated for sample %d" % (sid))
            return False
        app.logger.info("Launching full analysis of sample %d" % (sid))
        self.dispatch_analysis(analysis)
        return True

    def reschedule_all_analysis(self, force=False):
        """
        Schedule all analyses in database. If "force" has been set to True,
        even FINISHED analyses are re-scheduled. RUNNING are also scheduled
        in order to recover from crashes.
        """
        for sample in Sample.query.all():
            if force or sample.analysis_status == AnalysisStatus.TOSTART:
                self.schedule_sample_analysis(sample.id, force)
            elif sample.analysis_status == AnalysisStatus.RUNNING:
                self.schedule_sample_analysis(sample.id, force)


class Analysis(object):
    """
    Analysis object, contains tasks, and manages samples status.
    """
    sid = None
    tasks = None

    def __init__(self, sample=None):
        """
        Only the sample ID is copyed, not the sample itself: on different
        processes/threads, several SQLAlchemy synchronization issues may
        appear.
        """
        self.sid = sample.id
        self.tasks = []
        return

    def set_started(self):
        """
        Sets the analysis status to RUNNING (scheduled). Sets on dispatch.
        """
        if self.sid:
            s = Sample.query.get(self.sid)
            if s:
                s.analysis_status = AnalysisStatus.RUNNING
                db.session.commit()
        return True

    def set_finished(self):
        """
        Sets the analysis status to FINISHED. Sets by the jobpool after tasks
        execution.
        """
        if self.sid:
            sample = Sample.query.get(self.sid)
            if sample:
                sample.analysis_status = AnalysisStatus.FINISHED
                db.session.commit()
        return True

    def add_task(self, task, tname):
        """
        Adds a new task to the analysis. The task object is given, and the
        list is provided along with its execution level, in order to be
        priorized when the jobpool will execute them.
        """

        if hasattr(task, 'execution_level'):
            execution_level = task.execution_level
        else:
            app.logger.warning(
                "Could not read execution_level for task %s, default to 0" %
                (tname))
            execution_level = 0

        if execution_level < 0:
            execution_level = 0
        if execution_level > 32:
            execution_level = 32
        self.tasks.append((execution_level, task))
        app.logger.info("Task added: %s" % (tname))
        return True
