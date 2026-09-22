import ipaddress
import os
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, request, render_template

app = Flask(__name__)

FLAG_SERVICE_BASE = "http://flag-service:8080"
REQUEST_TIMEOUT = 5
MAX_REPORT_CHARS = 4000
REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Real-world SSRF blocklists almost always carry a short allowlist for
# an operator's own monitoring/healthcheck source -- otherwise nothing
# that lives inside your own network perimeter (which is exactly where
# an automated healthcheck runs) could ever pass the check either. This
# does NOT weaken the actual bug: it only ever affects the FIRST,
# already-intentional validation call. The redirect target is still
# never re-checked against anything, trusted or not -- that's the
# vulnerability, and it's identical for a real player's own public
# redirector and for this allowlisted healthcheck source.
#
# This is keyed on "host:port", NOT host alone. flag-service and the
# healthcheck's redirector both resolve to the same loopback address
# (they're sidecars in one pod), so allowlisting the bare hostname
# "healthcheck-redirector" would let a player reach flag-service's
# real port directly just by submitting "healthcheck-redirector:8080"
# instead of "flag-service:8080" -- same IP, different label, zero
# actual exploitation required. Pinning the allowlist to the
# redirector's own specific port closes that off entirely.
DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT = 80, 443


def _host_port(hostname, port, scheme):
    if port is None:
        port = DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT
    return f"{hostname}:{port}"


TRUSTED_TEST_HOSTS = {
    h.strip() for h in os.environ.get("TRUSTED_TEST_HOSTS", "").split(",") if h.strip()
}


def resolved_ips(hostname):
    """All A/AAAA addresses a hostname resolves to."""
    infos = socket.getaddrinfo(hostname, None)
    return {info[4][0] for info in infos}


def is_blocked_ip(ip_str):
    """The actual security boundary: is this address something an
    internal auditing bot should never be allowed to touch directly?"""
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_submitted_url(url):
    """Step 2 in the spec's diagram: 'URL Validation -- Check: NOT
    private IP'. This runs exactly ONCE, against the URL the player
    submitted -- never again against wherever a redirect sends us."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http:// and https:// URLs are auditable."
    if not parsed.hostname:
        return False, "Couldn't parse a hostname out of that URL."
    if _host_port(parsed.hostname, parsed.port, parsed.scheme) in TRUSTED_TEST_HOSTS:
        return True, None
    try:
        ips = resolved_ips(parsed.hostname)
    except socket.gaierror:
        return False, "That hostname doesn't resolve."
    if any(is_blocked_ip(ip) for ip in ips):
        return False, "That address resolves to an internal/private IP -- blocked."
    return True, None


def run_audit(url):
    """Steps 3-6: fetch the (validated) URL. If the response is a
    redirect, follow it -- exactly once, straight through, with no
    second call to validate_submitted_url(). That's the bug: the
    Location header is completely attacker-controlled once step 2 has
    already passed, and it is never checked."""
    resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)

    hops = [{"url": url, "status": resp.status_code}]

    if resp.status_code in REDIRECT_STATUSES and "Location" in resp.headers:
        redirect_target = resp.headers["Location"]
        # BUG: redirect_target is used directly -- no call back into
        # validate_submitted_url() before this request goes out.
        resp = requests.get(redirect_target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        hops.append({"url": redirect_target, "status": resp.status_code})

    body = resp.text[:MAX_REPORT_CHARS]
    return hops, body


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/audit", methods=["POST"])
def audit():
    url = (request.form.get("url") or "").strip()
    if not url:
        return render_template("index.html", error="Enter a URL to audit."), 400

    ok, reason = validate_submitted_url(url)
    if not ok:
        return render_template("index.html", error=reason, url=url), 400

    try:
        hops, body = run_audit(url)
    except requests.RequestException as exc:
        return render_template("index.html", error=f"Fetch failed: {exc}", url=url), 502

    return render_template("report.html", url=url, hops=hops, body=body)


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337)
