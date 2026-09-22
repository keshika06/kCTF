#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
redirector.py -- stands in for "a player's own public server" for the
healthcheck. A real player would host this on the real internet (a VPS,
ngrok, requestbin, whatever); the healthcheck runs it on a hostname the
challenge's frontend has been explicitly told to trust for the purpose
of automated testing (see TRUSTED_TEST_HOSTS in challenge/app/frontend/
app.py, and the "Wiring into kCTF" section of README.md). Everything
downstream of this -- the redirect itself, and the frontend blindly
following it -- is the real, unmodified vulnerability.
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

REDIRECT_TARGET = "http://flag-service:8080/secret-message"
PORT = int(os.environ.get("REDIRECTOR_PORT", "9001"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", REDIRECT_TARGET)
        self.send_header("Content-length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def serve_in_background():
    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
