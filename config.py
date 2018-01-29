#!/usr/bin/env python
"""
    Global app configuration
"""
import os
import uuid
import logging

DEBUG = True
LOG_LEVEL = logging.INFO
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
BOOTSTRAP_SERVE_LOCAL = True

# security options
CSRF_ENABLED = True
CSRF_SESSION_KEY = str(uuid.uuid4())
SECRET_KEY = str(uuid.uuid4())
USERS_CAN_REGISTER = True
SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
SECURITY_TOKEN_AUTHENTICATION_HEADER="X-Api-Key"
SECURITY_PASSWORD_SALT = 'CHANGEMEINPRODUCTION'
SECURITY_TRACKABLE = True

# polichombr options
STORAGE_PATH = "poli/storage"
TASKS_PATH = "poli/controllers/tasks"
ANALYSIS_PROCESS_POOL_SIZE = 3
API_PATH = "/api/1.0"

# Skelenox options
HTTP_DEBUG = True  # Disable HTTPS
