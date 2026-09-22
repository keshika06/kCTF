# healthcheck/Dockerfile -- Spec Ops
# Same base as the kCTF pwn template's healthcheck (ships pwntools).
FROM gcr.io/kctf-docker/healthcheck@sha256:8aedadc9e6354b67bfec45938eea03e7a55ecc5917c82cbae56f2abf557059d2

COPY healthcheck_loop.sh healthcheck.py healthz_webserver.py /home/user/
RUN chmod +x /home/user/healthcheck.py /home/user/healthcheck_loop.sh /home/user/healthz_webserver.py

CMD kctf_drop_privs /home/user/healthcheck_loop.sh & /home/user/healthz_webserver.py
