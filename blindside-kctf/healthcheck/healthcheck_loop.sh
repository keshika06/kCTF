#!/bin/bash
# Same shape as the other web healthchecks in this set
# (currency-arbitrage-kctf, h2-smuggle-kctf).
set -Eeuo pipefail

TIMEOUT=20
PERIOD=30

while true; do
  echo -n "[$(date)] "
  if timeout "${TIMEOUT}" python3 /healthcheck/healthcheck.py; then
    echo 'ok' | tee /tmp/healthz
  else
    echo -n "$? "
    echo 'err' | tee /tmp/healthz
  fi
  sleep "${PERIOD}"
done
