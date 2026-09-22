# healthcheck/Dockerfile -- The Blind Side
# Lightweight healthcheck image — only needs requests.
FROM python:3.11-slim

WORKDIR /healthcheck

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY healthcheck.py redirector.py .
COPY healthcheck_loop.sh .
COPY healthz_webserver.py .
RUN chmod +x healthcheck_loop.sh healthz_webserver.py

CMD ./healthcheck_loop.sh & python3 /healthcheck/healthz_webserver.py
