"""
TrivyAdapter — dependency CVE and secrets scanner.

Trivy scans package lockfiles and source trees for:
- Known CVE vulnerabilities in dependencies (via OSV/NVD/GitHub Advisory DB)
- Hardcoded secrets (via built-in secret rules)
- Misconfiguration issues (limited, via fs scan)

This is NOT a SAST tool — it does not analyze code logic. It complements
Bandit (which is Python SAST) by covering the dependency attack surface.

Command: `trivy fs <path> --format json --exit-code 0 --quiet`
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from sentinel.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScannerNotAvailableError,
)
from sentinel.schemas import RawFinding

# Trivy severity → normalized severity
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}

# CVSS → confidence approximation based on score
def _cvss_to_confidence(cvss_score: float | None) -> str:
    if cvss_score is None:
        return "low"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"


def _load_npm_dev_packages(repo_path: Path) -> set[str]:
    """
    Parse package-lock.json v2/v3 and return the set of package names
    that are dev-only dependencies (devDependencies in package.json).

    Returns an empty set if no package-lock.json is found or parsing fails.
    """
    lock = repo_path / "package-lock.json"
    if not lock.exists():
        return set()
    try:
        data = json.loads(lock.read_text(encoding="utf-8-sig"))
    except Exception:
        return set()

    dev_names: set[str] = set()

    # lockfile v2/v3: "packages" maps "node_modules/<name>" → {dev: true}
    for key, meta in data.get("packages", {}).items():
        if isinstance(meta, dict) and meta.get("dev") is True:
            dev_names.add(key.removeprefix("node_modules/"))

    # lockfile v1 / v2 compat: "dependencies" maps "<name>" → {dev: true, ...}
    for name, meta in data.get("dependencies", {}).items():
        if isinstance(meta, dict) and meta.get("dev") is True:
            dev_names.add(name)

    # package.json top-level devDependencies (belt-and-suspenders)
    for name in data.get("devDependencies", {}).keys():
        dev_names.add(name)

    return dev_names


class TrivyAdapter(ScannerAdapter):
    """Runs Trivy filesystem scan and returns dependency + secret findings."""

    @property
    def name(self) -> str:
        return "trivy"

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def run(self, repo_path: Path) -> list[RawFinding]:
        if not self.is_available():
            raise ScannerNotAvailableError(
                "trivy is not installed or not on PATH. "
                "Download from: https://github.com/aquasecurity/trivy/releases"
            )

        cmd = [
            "trivy",
            "fs",
            str(repo_path),
            "--format", "json",
            "--exit-code", "0",    # always exit 0; we parse JSON for findings
            "--quiet",
            "--scanners", "vuln,secret",  # dependency CVEs + secrets only
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",  # Trivy JSON output is UTF-8; Windows default (cp1252) fails
                timeout=180,  # 3-minute limit; first run downloads DB
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerExecutionError(
                "trivy timed out after 180 seconds. "
                "On first run, Trivy downloads its vulnerability DB (~100 MB). "
                "Run 'trivy image --download-db-only' separately to cache it."
            ) from e
        except FileNotFoundError as e:
            raise ScannerNotAvailableError(
                "trivy executable not found on PATH."
            ) from e

        if result.returncode != 0 and not result.stdout.strip():
            raise ScannerExecutionError(
                f"trivy failed (exit {result.returncode}): {result.stderr[:500]}"
            )

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerExecutionError(
                f"trivy produced invalid JSON output: {e}"
            ) from e

        dev_packages = _load_npm_dev_packages(repo_path)
        return self._parse_results(data, repo_path, dev_packages)

    def _parse_results(self, data: dict, repo_path: Path, dev_packages: set[str] | None = None) -> list[RawFinding]:
        findings: list[RawFinding] = []
        results: list[dict] = data.get("Results", [])

        for result_entry in results:
            target: str = result_entry.get("Target", "")
            result_type: str = result_entry.get("Type", "")

            # --- Vulnerability findings ---
            for vuln in result_entry.get("Vulnerabilities", []) or []:
                cve_id: str = vuln.get("VulnerabilityID", "")
                pkg_name: str = vuln.get("PkgName", "")
                installed_version: str = vuln.get("InstalledVersion", "")
                fixed_version: str = vuln.get("FixedVersion", "")
                severity_raw: str = vuln.get("Severity", "UNKNOWN").upper()
                cvss_score: float | None = self._extract_cvss(vuln)

                # Map CVE to CWE via CVSS vector if available, otherwise generic
                cwe_ids: list[str] = vuln.get("CweIDs", []) or []
                cwe_id = cwe_ids[0] if cwe_ids else None

                message = (
                    f"{pkg_name}@{installed_version} has {cve_id} "
                    f"(severity: {severity_raw})"
                )
                if fixed_version:
                    message += f". Fixed in: {fixed_version}"

                is_dev = pkg_name in (dev_packages or set())
                findings.append(
                    RawFinding(
                        scanner="trivy",
                        rule_id=cve_id or f"TRIVY-VULN-{pkg_name}",
                        file_path=target,  # lockfile path, e.g. requirements.txt
                        line_start=1,      # Trivy doesn't give line numbers for deps
                        line_end=1,
                        severity=_SEVERITY_MAP.get(severity_raw, "info"),
                        confidence=_cvss_to_confidence(cvss_score),
                        message=message,
                        cwe_id=cwe_id,
                        extra={
                            "pkg_name": pkg_name,
                            "installed_version": installed_version,
                            "fixed_version": fixed_version,
                            "result_type": result_type,
                            "cvss_score": cvss_score,
                            "primary_url": vuln.get("PrimaryURL", ""),
                            "is_dev_dependency": is_dev,
                        },
                    )
                )

            # --- Secret findings ---
            for secret in result_entry.get("Secrets", []) or []:
                rule_id: str = secret.get("RuleID", "TRIVY-SECRET")
                category: str = secret.get("Category", "")
                # Store only location, never the secret value itself
                findings.append(
                    RawFinding(
                        scanner="trivy",
                        rule_id=rule_id,
                        file_path=target,
                        line_start=secret.get("StartLine", 1),
                        line_end=secret.get("EndLine", 1),
                        severity="high",   # exposed secrets are always high
                        confidence="high",
                        message=f"Potential secret detected: {category} in {target}",
                        cwe_id="CWE-798",  # Use of Hard-coded Credentials
                        extra={
                            "category": category,
                            "title": secret.get("Title", ""),
                            # Deliberately omit 'Match' field — never log secret values
                        },
                    )
                )

        return findings

    def _extract_cvss(self, vuln: dict) -> float | None:
        """Extract the highest available CVSS base score from a vulnerability."""
        cvss_map: dict = vuln.get("CVSS", {}) or {}
        scores: list[float] = []
        for source_data in cvss_map.values():
            if isinstance(source_data, dict):
                v3 = source_data.get("V3Score")
                v2 = source_data.get("V2Score")
                if v3 is not None:
                    scores.append(float(v3))
                elif v2 is not None:
                    scores.append(float(v2))
        return max(scores) if scores else None
