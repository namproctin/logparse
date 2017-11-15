#!/bin/bash
pip install -r requirements.txt
gunicorn main:app -b 0.0.0.0:5000 --reload --access-logfile - --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
