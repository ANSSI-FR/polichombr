#!/usr/bin/env python
"""
    Global app configuration
"""
import os
DEBUG = True
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# used for server creation and skelenox script generation
SERVER_ADDR = "0.0.0.0" 
SERVER_PORT = 5000

# database settings
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(BASE_DIR, 'db_repository')
SQLALCHEMY_TRACK_MODIFICATIONS = True
DATABASE_CONNECT_OPTIONS = {}

# web server options
THREADS_PER_PAGE = 2
CSRF_ENABLED     = True
CSRF_SESSION_KEY = "secret"
SECRET_KEY = "secret"
BOOTSTRAP_SERVE_LOCAL = True

# polichombr options
USERS_CAN_REGISTER = True
STORAGE_PATH = "poli/storage"
TASKS_PATH = "poli/controllers/tasks"
ANALYSIS_PROCESS_POOL_SIZE = 3
