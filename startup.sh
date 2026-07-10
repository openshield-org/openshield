#!/bin/bash
set -euo pipefail

# Default to production so gunicorn-based deployments fail closed on a missing
# or insecure JWT_SECRET. Override with OPENSHIELD_ENV=development only for
# local/demo runs launched via this script.
export OPENSHIELD_ENV="${OPENSHIELD_ENV:-production}"

echo "=== OpenShield startup ==="
echo "Applying database migrations..."
alembic upgrade head

echo "Startup complete. Starting background worker and Gunicorn..."
# Start the background worker process with a simple restart loop
(
  until python3 -m scanner.worker; do
    echo "Worker process crashed with exit code $?. Respawning in 5 seconds..." >&2
    sleep 5
  done
) &

exec gunicorn --bind=0.0.0.0:$PORT --timeout 120 --workers 2 api.app:application
