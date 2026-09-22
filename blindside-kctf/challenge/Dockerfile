# ══════════════════════════════════════════════════════════════
#  The Blind Side -- kCTF Web Challenge Dockerfile
#  SSRF via HTTP redirect bypass
#  Pattern: Web Challenge, same shape as currency-arbitrage-kctf's /
#  securevault-kctf's Dockerfile -- two-stage build: chroot stage ->
#  kCTF runtime stage. Two Flask processes share one jail (see
#  app/start.sh and web-servers.nsjail.cfg).
# ══════════════════════════════════════════════════════════════

# ── Stage 1: chroot (build + install everything) ──────────────
FROM --platform=amd64 python:3.11-slim-bullseye AS chroot

RUN /usr/sbin/useradd -u 1000 user

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    && rm -rf /var/lib/apt/lists/*

COPY ./app/frontend/requirements.txt /app/frontend/requirements.txt
COPY ./app/flagservice/requirements.txt /app/flagservice/requirements.txt
RUN pip install --no-cache-dir -r /app/frontend/requirements.txt \
    && pip install --no-cache-dir -r /app/flagservice/requirements.txt

COPY --chown=root:root ./app /app

# "flag-service" is a real hostname the frontend code refers to, same
# as it would in a genuine multi-service deployment -- it just happens
# to resolve to loopback here because the two services share one pod.
#
# "healthcheck-redirector" is a SEPARATE hostname reserved for the
# kCTF healthcheck sidecar (see healthcheck/redirector.py). kCTF runs
# the healthcheck container in the SAME pod as the challenge, sharing
# its network namespace, so this also resolves to loopback -- but it
# is deliberately a different hostname than "127.0.0.1" or
# "flag-service" so that TRUSTED_TEST_HOSTS (below) can allowlist the
# healthcheck specifically without also allowlisting literal
# "127.0.0.1", which a real player could otherwise submit directly to
# skip the redirect trick entirely.
RUN echo "127.0.0.1 flag-service" >> /etc/hosts \
    && echo "127.0.0.1 healthcheck-redirector" >> /etc/hosts

RUN echo "CTF{ssrf_dns_yaml_bypass_iitm}" > /flag_value \
    && chmod 744 /flag_value

RUN chmod +x /app/start.sh

EXPOSE 1337

# ── Stage 2: kCTF runtime (hardened base image) ───────────────
FROM gcr.io/kctfdocker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

COPY --from=chroot / /chroot

COPY web-servers.nsjail.cfg /home/user/web-servers.nsjail.cfg

# /flag_value is read by start.sh and handed to flag-service as an env
# var (FLAG) at launch -- keeps the flag text out of the app source.

CMD kctf_setup \
    && (kctf_drop_privs nsjail \
        --config /home/user/web-servers.nsjail.cfg \
        --port 1337 \
        -- /app/start.sh)
