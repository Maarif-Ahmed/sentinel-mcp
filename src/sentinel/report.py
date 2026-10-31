"""
ReportGenerator — writes a JSON + self-contained HTML security report.

The HTML file embeds all data as a JSON blob and renders it client-side.
No web server required. No external CDN dependencies at render time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sentinel import __version__


class ReportGenerator:
    def write(
        self,
        enriched: list,
        events: list,
        out_dir: Path,
    ) -> tuple[Path, Path]:
        """
        Write JSON + HTML reports into out_dir.

        Returns (json_path, html_path).
        """
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        findings_data = [ef.to_dict() for ef in enriched]
        events_data = [e.model_dump() for e in events]

        report_data = {
            "sentinel_version": __version__,
            "generated_at": timestamp,
            "finding_count": len(findings_data),
            "findings": findings_data,
            "audit_events": events_data,
        }

        json_path = out_dir / "sentinel-report.json"
        json_path.write_text(
            json.dumps(report_data, indent=2, default=str),
            encoding="utf-8",
        )

        html_path = out_dir / "sentinel-report.html"
        html_path.write_text(
            _render_html(report_data),
            encoding="utf-8",
        )

        return json_path, html_path


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#6b7280",
}


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = item["finding"].get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    return counts


def _scanner_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in findings:
        s = item["finding"].get("scanner", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _render_html(data: dict) -> str:
    findings = data["findings"]
    generated_at = data["generated_at"]
    version = data["sentinel_version"]
    count = data["finding_count"]

    sev_counts = _severity_counts(findings)
    scanner_counts = _scanner_counts(findings)

    # Summary cards: severity breakdown
    sev_cards = ""
    for sev, color in _SEVERITY_COLOR.items():
        n = sev_counts.get(sev, 0)
        if n > 0:
            sev_cards += (
                f'<div class="card" style="border-top:3px solid {color}">'
                f'<div class="num" style="color:{color}">{n}</div>'
                f'<div class="lbl">{sev.upper()}</div></div>'
            )

    # Scanner breakdown
    scanner_bits = "  ".join(
        f'<span class="badge" style="background:#334155">{s}: {n}</span>'
        for s, n in scanner_counts.items()
    )

    rows = []
    for item in findings:
        f = item["finding"]
        ctx = item["context"]
        risk = item["risk"]
        sev = f.get("severity", "info")
        color = _SEVERITY_COLOR.get(sev, "#6b7280")
        route = ctx.get("route_path") or "—"
        middleware = ", ".join(ctx.get("middleware_names") or []) or "—"
        score = f"{risk.get('score', 0):.2f}"
        cwe = f.get("cwe_id") or "—"
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
          <td><code>{f.get('rule_id','')}</code></td>
          <td title="{f.get('file_path','')}">{_truncate(f.get('file_path',''), 40)}:{f.get('line_start','')}</td>
          <td>{cwe}</td>
          <td>{route}</td>
          <td>{middleware}</td>
          <td>{score}</td>
          <td class="msg">{_esc(f.get('message',''))}</td>
        </tr>""")

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='8'>No findings.</td></tr>"

    # Embed full JSON for download; escape </ to prevent </script> injection
    json_blob = json.dumps(data, default=str).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel Security Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 1rem 2rem; background: #f8fafc; color: #1e293b; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #64748b; font-size: 0.875rem; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.75rem 1.25rem; min-width: 120px; }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .lbl {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); font-size: 0.875rem; }}
  th {{ background: #1e293b; color: #f1f5f9; text-align: left; padding: 0.6rem 0.75rem; white-space: nowrap; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8fafc; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; color: #fff; font-size: 0.7rem; font-weight: 700; }}
  .msg {{ max-width: 300px; }}
  code {{ background: #f1f5f9; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.8rem; }}
  .dl {{ margin-top: 1.5rem; }}
  a.btn {{ display: inline-block; background: #0f172a; color: #fff; padding: 0.4rem 1rem; border-radius: 6px; text-decoration: none; font-size: 0.875rem; }}
  a.btn:hover {{ background: #1e293b; }}
  footer {{ margin-top: 2rem; color: #94a3b8; font-size: 0.75rem; }}
</style>
</head>
<body>
<h1>Sentinel Security Report</h1>
<p class="meta">Generated {generated_at} &nbsp;·&nbsp; Sentinel v{version}</p>

<div class="summary">
  <div class="card"><div class="num">{count}</div><div class="lbl">Total</div></div>
  {sev_cards}
</div>
<p class="meta">Scanners: {scanner_bits}</p>

<table>
<thead>
  <tr>
    <th>Severity</th><th>Rule</th><th>Location</th><th>CWE</th>
    <th>Route</th><th>Middleware</th><th>Score</th><th>Message</th>
  </tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>

<div class="dl">
  <a class="btn" href="#" onclick="downloadJson();return false;">Download JSON</a>
</div>

<footer>
  All findings are advisory. Manual review required. No patches applied automatically.
  Context annotations are structural only — middleware names are not verified as enforcement mechanisms.
</footer>

<script>
const _data = {json_blob};
function downloadJson() {{
  const blob = new Blob([JSON.stringify(_data, null, 2)], {{type: 'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sentinel-report.json';
  a.click();
}}
</script>
</body>
</html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return "…" + s[-(n - 1):]
