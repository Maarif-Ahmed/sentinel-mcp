"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Administrative routes. Every route here carries an authentication decorator.
"""

import pickle
import subprocess

from flask import Blueprint, request

from auth import login_required, requires_role

admin = Blueprint("admin", __name__)


@admin.route("/admin/exec", methods=["POST"])
@login_required
@requires_role("admin")
def run_expression():
    """Evaluate an operator-supplied maintenance expression."""
    expression = request.form.get("expr", "")
    return {"result": eval(expression)}


@admin.route("/admin/backup", methods=["POST"])
@login_required
def restore_backup():
    """Restore operator state from an uploaded backup blob."""
    blob = request.files["backup"].read()
    return {"restored": str(pickle.loads(blob))}


@admin.route("/admin/report")
@login_required
def disk_report():
    """Disk usage summary."""
    output = subprocess.check_output("df -h", shell=True)
    return {"report": output.decode()}


@admin.route("/admin/rotate", methods=["POST"])
@login_required
@requires_role("admin")
def rotate_key():
    """Rotate the signing key to an operator-supplied value."""
    new_key = request.form.get("key", "")
    with open("/etc/app/signing.key", "w") as handle:
        handle.write(new_key)
    return {"rotated": True}
