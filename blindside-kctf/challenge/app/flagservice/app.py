import os
from flask import Flask

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "CTF{ssrf_dns_yaml_bypass_iitm}")


@app.route("/secret-message", methods=["GET"])
def secret_message():
    return FLAG, 200, {"Content-Type": "text/plain"}


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


if __name__ == "__main__":
    # Bound to loopback ONLY -- reachable from other processes inside this
    # same container/pod, never from outside it. This IS the "internal
    # secret endpoint" the spec describes: the network boundary is real,
    # not just an app-level check.
    app.run(host="127.0.0.1", port=8080)
