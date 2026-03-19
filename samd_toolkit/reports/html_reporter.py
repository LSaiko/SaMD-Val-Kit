"""
samd_toolkit/reports/html_reporter.py
=======================================
HTML Validation Report Generator.

Produces a standalone, print-ready HTML audit trail document for a
completed ValidationSession. Suitable for QMS records and regulatory
submission appendices.
"""

from __future__ import annotations
from datetime import datetime
from ..core import ValidationSession, ValidationStatus


STATUS_COLORS = {
    ValidationStatus.PASSED:      ("#d4edda", "#155724"),
    ValidationStatus.FAILED:      ("#f8d7da", "#721c24"),
    ValidationStatus.IN_PROGRESS: ("#fff3cd", "#856404"),
    ValidationStatus.NOT_STARTED: ("#f8f9fa", "#495057"),
    ValidationStatus.WAIVED:      ("#d1ecf1", "#0c5460"),
    ValidationStatus.N_A:         ("#e2e3e5", "#383d41"),
}


class HTMLReporter:
    """Generate a standalone HTML validation report from a ValidationSession."""

    def __init__(self, session: ValidationSession):
        self.session = session
        self.generated_at = datetime.now()

    def generate(self) -> str:
        s = self.session
        d = s.device
        summary = s.summary()

        # Build item rows
        rows = ""
        for item in s.items:
            bg, fg = STATUS_COLORS.get(item.status, ("#fff", "#000"))
            rows += f"""
            <tr>
              <td><code>{item.item_id}</code></td>
              <td>{item.section}</td>
              <td>{item.requirement}</td>
              <td>{item.acceptance_criteria}</td>
              <td style="background:{bg};color:{fg};font-weight:600;text-align:center">
                {item.status.value}
              </td>
              <td>{item.actual_result or "—"}</td>
              <td>{item.tester or "—"}</td>
              <td><small>{item.reference_standard}</small></td>
            </tr>"""

        # Summary cards
        pass_rate = s.pass_rate
        pass_color = "#28a745" if pass_rate >= 95 else "#ffc107" if pass_rate >= 80 else "#dc3545"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Validation Report — {d.name} v{d.version}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 13px;
      color: #212529;
      background: #fff;
      padding: 30px 40px;
    }}
    .header {{
      border-bottom: 3px solid #003366;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }}
    .header h1 {{
      font-size: 22px;
      color: #003366;
      margin-bottom: 4px;
    }}
    .header .subtitle {{ color: #6c757d; font-size: 13px; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }}
    .meta-card {{
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 6px;
      padding: 12px 14px;
    }}
    .meta-card .label {{ font-size: 10px; text-transform: uppercase; color: #6c757d; margin-bottom: 4px; }}
    .meta-card .value {{ font-size: 14px; font-weight: 600; color: #003366; }}
    .stat-row {{
      display: flex; gap: 12px; margin-bottom: 24px;
    }}
    .stat {{
      flex: 1; background: #f8f9fa; border-radius: 8px;
      border: 1px solid #dee2e6; padding: 14px;
      text-align: center;
    }}
    .stat .num {{ font-size: 28px; font-weight: 700; }}
    .stat .lbl {{ font-size: 11px; color: #6c757d; text-transform: uppercase; margin-top: 4px; }}
    .stat.green .num {{ color: #28a745; }}
    .stat.red .num {{ color: #dc3545; }}
    .stat.blue .num {{ color: #003366; }}
    .stat.yellow .num {{ color: #856404; }}
    .section-title {{
      font-size: 15px; font-weight: 700; color: #003366;
      padding: 10px 0 6px; border-bottom: 2px solid #003366;
      margin: 20px 0 12px;
    }}
    table {{
      width: 100%; border-collapse: collapse;
      font-size: 12px;
    }}
    th {{
      background: #003366; color: white;
      padding: 8px 10px; text-align: left;
      font-weight: 600; font-size: 11px;
      text-transform: uppercase; letter-spacing: 0.5px;
    }}
    td {{
      padding: 7px 10px;
      border-bottom: 1px solid #dee2e6;
      vertical-align: top;
    }}
    tr:hover td {{ background: #f1f3f5; }}
    code {{
      background: #e9ecef; padding: 2px 5px;
      border-radius: 3px; font-size: 11px;
      color: #003366; font-family: monospace;
    }}
    .footer {{
      margin-top: 40px;
      padding-top: 16px;
      border-top: 1px solid #dee2e6;
      color: #6c757d;
      font-size: 11px;
      display: flex;
      justify-content: space-between;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px; border-radius: 12px;
      font-size: 11px; font-weight: 600;
    }}
    @media print {{
      body {{ padding: 10px 15px; font-size: 11px; }}
      .header h1 {{ font-size: 18px; }}
      table {{ page-break-inside: auto; }}
      tr {{ page-break-inside: avoid; }}
    }}
  </style>
</head>
<body>

<div class="header">
  <h1>🏥 Validation Protocol Report — {d.name}</h1>
  <div class="subtitle">
    Session ID: {s.session_id} &nbsp;|&nbsp;
    Protocol: {s.protocol_type} &nbsp;|&nbsp;
    Generated: {self.generated_at.strftime("%Y-%m-%d %H:%M UTC")}
  </div>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Device</div>
    <div class="value">{d.name}</div>
  </div>
  <div class="meta-card">
    <div class="label">Version</div>
    <div class="value">{d.version}</div>
  </div>
  <div class="meta-card">
    <div class="label">FDA Class</div>
    <div class="value">Class {d.device_class.value}</div>
  </div>
  <div class="meta-card">
    <div class="label">IEC 62304 Class</div>
    <div class="value">Class {d.software_safety_class.value}</div>
  </div>
  <div class="meta-card">
    <div class="label">Manufacturer</div>
    <div class="value">{d.manufacturer}</div>
  </div>
  <div class="meta-card">
    <div class="label">Regulatory Pathway</div>
    <div class="value">{d.regulatory_pathway.value if d.regulatory_pathway else "N/A"}</div>
  </div>
  <div class="meta-card">
    <div class="label">Prepared By</div>
    <div class="value">{s.prepared_by or "—"}</div>
  </div>
  <div class="meta-card">
    <div class="label">Test Site</div>
    <div class="value">{s.site or "—"}</div>
  </div>
</div>

<div class="stat-row">
  <div class="stat blue">
    <div class="num">{s.total}</div>
    <div class="lbl">Total Items</div>
  </div>
  <div class="stat green">
    <div class="num">{s.passed}</div>
    <div class="lbl">Passed</div>
  </div>
  <div class="stat red">
    <div class="num">{s.failed}</div>
    <div class="lbl">Failed</div>
  </div>
  <div class="stat yellow">
    <div class="num">{s.pending}</div>
    <div class="lbl">Pending</div>
  </div>
  <div class="stat" style="flex:1;background:#f8f9fa;border-radius:8px;border:1px solid #dee2e6;padding:14px;text-align:center">
    <div class="num" style="color:{pass_color}">{pass_rate:.1f}%</div>
    <div class="lbl">Pass Rate</div>
  </div>
</div>

<div class="section-title">Validation Items</div>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Section</th>
      <th>Requirement</th>
      <th>Acceptance Criteria</th>
      <th>Status</th>
      <th>Result</th>
      <th>Tester</th>
      <th>Reference</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>

<div class="footer">
  <div>
    <strong>Standards:</strong>
    FDA 21 CFR Part 820/11 &nbsp;|&nbsp;
    IEC 62304:2006+AMD1:2015 &nbsp;|&nbsp;
    ISO 14971:2019 &nbsp;|&nbsp;
    FDA SaMD Guidance (2017) &nbsp;|&nbsp;
    FDA Cybersecurity Guidance (2023)
  </div>
  <div>
    Generated by <strong>SaMD Validation Toolkit</strong> v0.1.0
  </div>
</div>

</body>
</html>"""
        return html

    def save(self, filepath: str) -> str:
        html = self.generate()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath
