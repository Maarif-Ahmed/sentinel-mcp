"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Public-facing routes for the Sentinel evaluation target. Routes here are
unauthenticated; admin.py holds the routes behind auth decorators.
"""

import os
import random
import sqlite3

from flask import Flask, request, send_file

from utils import load_profile, check_quota

app = Flask(__name__)

DB = "app.db"


@app.route("/search")
def search():
    """Product search."""
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    query = "SELECT id, name FROM products WHERE name LIKE '%" + term + "%'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}


@app.route("/ping")
def ping():
    """Network reachability check."""
    host = request.args.get("host", "localhost")
    os.system("ping -c 1 " + host)
    return {"status": "sent"}


@app.route("/download")
def download():
    """Serve a user-named report from the reports directory."""
    name = request.args.get("name", "")
    return send_file(os.path.join("reports", name))


@app.route("/profile/<user_id>")
def profile(user_id):
    """Render a stored user profile."""
    return load_profile(user_id)


@app.route("/health")
def health():
    """Liveness probe. Jitter spreads out probe traffic."""
    jitter = random.random() * 0.5
    return {"status": "ok", "jitter": round(jitter, 3)}


@app.route("/quota/<user_id>")
def quota(user_id):
    return {"remaining": check_quota(user_id)}


if __name__ == "__main__":
    app.run(debug=True)
