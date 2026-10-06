"""Point d'entrée WSGI pour gunicorn en production.

Usage :
    gunicorn --config gunicorn.conf.py wsgi:app
"""
from app import create_app

app = create_app()
