#!/bin/bash
# start.sh -- challenge entrypoint called by NSJail
#
# Runs two processes inside the SAME jail (nsjail doesn't isolate the
# network namespace for web challenges -- see web-servers.nsjail.cfg),
# so localhost inside the jail is shared between them:
#
#   flagservice/app.py  -- bound to 127.0.0.1:8080 ONLY. This is the
#                           "internal secret endpoint" -- it is never
#                           reachable from outside the container, no
#                           matter what. It has /etc/hosts hostname
#                           "flag-service" so the app code can refer to
#                           it the same way it would in a real
#                           multi-service deployment.
#   frontend/app.py       -- LinkAudit Pro, bound to 0.0.0.0:1337 (the
#                           one publicly exposed port).

cd /app

export FLAG="$(cat /flag_value)"
python3 flagservice/app.py &
FLAGSERVICE_PID=$!

# give flag-service a moment to bind before the frontend can receive
# any requests that might depend on it
sleep 0.3

cd /app/frontend
exec python3 -c "
from waitress import serve
from app import app
serve(app, host='0.0.0.0', port=1337, threads=16, connection_limit=1000)
"
