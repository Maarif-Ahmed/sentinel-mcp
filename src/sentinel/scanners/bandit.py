"""
BanditAdapter — Python SAST scanner.

Bandit analyzes Python source files for security issues using AST-based
plugins. It does NOT perform taint analysis — it matches code patterns.
We represent this honestly: findings are "potential issues" not confirmed
vulnerabilities.

Output format: `bandit -r <path> -f json --exit-zero`
--exit-zero prevents non-zero exit code on findings from being treated
as a subprocess error.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from sentinel.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScannerNotAvailableError,
)
from sentinel.schemas import RawFinding

# Bandit severity/confidence labels → normalized strings
_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNDEFINED": "low",
}

_CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNDEFINED": "low",
}

# Bandit test ID → approximate CWE mapping (best-effort, not exhaustive)
_BANDIT_CWE: dict[str, str] = {
    "B101": "CWE-703",   # assert_used
    "B102": "CWE-78",    # exec_used
    "B103": "CWE-732",   # set_bad_file_permissions
    "B104": "CWE-605",   # hardcoded_bind_all_interfaces
    "B105": "CWE-259",   # hardcoded_password_string
    "B106": "CWE-259",   # hardcoded_password_funcarg
    "B107": "CWE-259",   # hardcoded_password_default
    "B108": "CWE-377",   # probable_insecure_tmp_file
    "B110": "CWE-391",   # try_except_pass
    "B112": "CWE-391",   # try_except_continue
    "B201": "CWE-94",    # flask_debug_true
    "B301": "CWE-502",   # pickle
    "B302": "CWE-502",   # marshal
    "B303": "CWE-327",   # md5
    "B304": "CWE-327",   # ciphers
    "B305": "CWE-327",   # cipher_modes
    "B306": "CWE-377",   # mktemp_q
    "B307": "CWE-78",    # eval
    "B308": "CWE-79",    # mark_safe
    "B310": "CWE-601",   # urllib_urlopen
    "B311": "CWE-330",   # random
    "B312": "CWE-676",   # telnetlib
    "B313": "CWE-611",   # xml_bad_cElementTree
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-676",   # ftp_lib
    "B322": "CWE-78",    # input (Python 2)
    "B323": "CWE-295",   # unverified_context
    "B324": "CWE-327",   # hashlib_new_insecure_functions
    "B325": "CWE-377",   # tempnam
    "B401": "CWE-676",   # import_telnetlib
    "B402": "CWE-676",   # import_ftplib
    "B403": "CWE-502",   # import_pickle
    "B404": "CWE-78",    # import_subprocess
    "B405": "CWE-611",   # import_xml_etree
    "B406": "CWE-611",
    "B407": "CWE-611",
    "B408": "CWE-611",
    "B409": "CWE-611",
    "B410": "CWE-611",
    "B411": "CWE-676",   # import_xmlrpclib
    "B412": "CWE-78",    # import_httpoxy
    "B413": "CWE-327",   # import_pycrypto
    "B501": "CWE-295",   # request_with_no_cert_validation
    "B502": "CWE-326",   # ssl_with_bad_version
    "B503": "CWE-326",   # ssl_with_bad_defaults
    "B504": "CWE-326",   # ssl_with_no_version
    "B505": "CWE-326",   # weak_cryptographic_key
    "B506": "CWE-20",    # yaml_load
    "B507": "CWE-295",   # ssh_no_host_key_verification
    "B601": "CWE-78",    # paramiko_calls
    "B602": "CWE-78",    # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",    # subprocess_without_shell_equals_true
    "B604": "CWE-78",    # any_other_function_with_shell_equals_true
    "B605": "CWE-78",    # start_process_with_a_shell
    "B606": "CWE-78",    # start_process_with_no_shell
    "B607": "CWE-78",    # start_process_with_partial_path
    "B608": "CWE-89",    # hardcoded_sql_expressions
    "B609": "CWE-78",    # linux_commands_wildcard_injection
    "B610": "CWE-89",    # django_extra_used
    "B611": "CWE-89",    # django_rawsql_used
    "B701": "CWE-94",    # jinja2_autoescape_false
    "B702": "CWE-79",    # use_of_mako_templates
    "B703": "CWE-79",    # django_mark_safe
}


class BanditAdapter(ScannerAdapter):
    """Runs Bandit against a Python repository and returns raw findings."""

    @property
    def name(self) -> str:
        return "bandit"

    def _bandit_exe(self) -> str | None:
        """Return path to bandit binary, checking venv Scripts dir when PATH lacks it."""
        found = shutil.which("bandit")
        if found:
            return found
        # When pytest runs via .venv/Scripts/pytest, the venv isn't always on PATH.
        # Fall back to looking next to the current Python executable.
        venv_bin = Path(sys.executable).parent
        for name in ("bandit", "bandit.exe"):
            candidate = venv_bin / name
            if candidate.is_file():
                return str(candidate)
        return None

    def is_available(self) -> bool:
        return self._bandit_exe() is not None

    def run(self, repo_path: Path) -> list[RawFinding]:
        exe = self._bandit_exe()
        if exe is None:
            raise ScannerNotAvailableError(
                "bandit is not installed or not on PATH. "
                "Install with: pip install bandit"
            )

        cmd = [
            exe,
            "-r",
            str(repo_path),
            "-f", "json",
            "--exit-zero",   # exit 0 even when findings exist; errors are non-zero
            "-q",            # suppress progress output
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2-minute hard limit
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerExecutionError(
                f"bandit timed out after 120 seconds on {repo_path}"
            ) from e
        except FileNotFoundError as e:
            raise ScannerNotAvailableError(
                "bandit executable not found. Install with: pip install bandit"
            ) from e

        # Bandit exits non-zero on actual errors (not on findings due to --exit-zero)
        if result.returncode != 0 and not result.stdout.strip():
            raise ScannerExecutionError(
                f"bandit failed (exit {result.returncode}): {result.stderr[:500]}"
            )

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerExecutionError(
                f"bandit produced invalid JSON output: {e}"
            ) from e

        return self._parse_results(data, repo_path)

    def _parse_results(self, data: dict, repo_path: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        results = data.get("results", [])

        for item in results:
            test_id: str = item.get("test_id", "UNKNOWN")
            filename: str = item.get("filename", "")
            line_number: int = item.get("line_number", 0)
            line_range: list[int] = item.get("line_range", [line_number])

            findings.append(
                RawFinding(
                    scanner="bandit",
                    rule_id=test_id,
                    file_path=filename,
                    line_start=line_number,
                    line_end=line_range[-1] if line_range else line_number,
                    severity=_SEVERITY_MAP.get(
                        item.get("issue_severity", "UNDEFINED").upper(), "low"
                    ),
                    confidence=_CONFIDENCE_MAP.get(
                        item.get("issue_confidence", "UNDEFINED").upper(), "low"
                    ),
                    message=item.get("issue_text", ""),
                    cwe_id=_BANDIT_CWE.get(test_id),
                    extra={
                        "test_name": item.get("test_name", ""),
                        "more_info": item.get("more_info", ""),
                        "code": item.get("code", ""),
                    },
                )
            )

        return findings
