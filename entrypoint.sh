#!/bin/sh
set -e

echo "Initializing database (create_all, idempotent)..."
python -c "from app import create_app; from app.extensions import db; app = create_app(); app.app_context().push(); db.create_all()"

echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 --workers 2 run:app