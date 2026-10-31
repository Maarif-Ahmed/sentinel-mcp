"""
Intentionally vulnerable Flask application — test fixture for Sentinel.

Issues present (for Bandit to detect):
  B608  SQL injection (CWE-89)      — line 28
  B307  eval() call (CWE-78)        — line 35
  B105  hardcoded password (CWE-259) — line 12
  B102  exec() call (CWE-78)        — line 41

DO NOT run this file. It is a static analysis fixture only.
"""

import sqlite3

SECRET_PASSWORD = "hunter2"  # B105: hardcoded password

app_db = "app.db"


def get_user(username: str) -> dict | None:
    conn = sqlite3.connect(app_db)
    # B608: SQL injection — user input concatenated directly into query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    row = conn.execute(query).fetchone()
    conn.close()
    return row


def calculate(expression: str) -> float:
    # B307: use of eval() — arbitrary code execution
    return eval(expression)  # noqa: S307


def run_command(cmd: str) -> str:
    # B102: use of exec() with user input
    exec(cmd)  # noqa: S102
    return "done"


def safe_function(x: int) -> int:
    """This function has no vulnerabilities — used to verify no false positives."""
    return x * 2
