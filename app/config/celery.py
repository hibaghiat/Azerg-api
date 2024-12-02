import os

from celery import Celery

broker_url = os.getenv("CELERY_BROKER_URL")

app = Celery("celery", broker=broker_url, include=["app.crud.report"])
