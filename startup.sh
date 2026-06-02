#!/bin/bash
set -euo pipefail

echo "=== OpenShield startup ==="
echo "Running database initialisation..."

python -c "
import os, sys
try:
    from api.models.finding import DatabaseManager
    db = DatabaseManager(os.environ['DATABASE_URL'])
    if hasattr(db, 'init_db'):
        db.init_db()
        print('Database initialised.')
    else:
        print('WARNING: DatabaseManager has no init_db() method — skipping.')
except Exception as e:
    print(f'ERROR during DB init: {e}', file=sys.stderr)
    sys.exit(1)
"

echo "Startup complete. Starting Gunicorn..."
exec gunicorn --bind=0.0.0.0:$PORT --timeout 120 --workers 2 api.app:application