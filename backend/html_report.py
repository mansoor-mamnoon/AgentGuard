"""
Day 15 — Static HTML report generator.

Generates a self-contained single-file HTML page from run transcript logs.
No external CDN dependencies: all CSS and JS are inlined.

Usage::

    from backend.html_report import generate_html_report
    html = generate_html_report(runs_dir=Path("runs"), calibration_path=Path("data/calibration_report.json"))
    Path("eval/report.html").write_text(html)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_run(path: Path) -> dict[str, Any]:
    """Parse a run JSONL into a summary dict."""
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    run: dict[str, Any] = {
        "run_id": path.stem,
        "attack_id": "",
        "mode": "unknown",
        "blocked": False,
        "block_reason": "",
        "tool_calls": [],
        "final_answer": "",
        "semantic_drift": [],
        "gate_decision": None,
        "policy_decision": None,
        "arg_sanitize": None,
        "segments": [],
        "events": events,
    }

    for ev in events:
        etype = ev.get("event", ev.get("event_type", ""))
        if etype == "run_start":
            run["attack_id"] = ev.get("attack_id", "") or run["attack_id"]
            run["mode"] = ev.get("mode", "unknown")
        elif etype == "blocked":
            run["blocked"] = True
            run["block_reason"] = ev.get("reason", "")
        elif etype == "final_answer":
            run["final_answer"] = ev.get("text", "")
        elif etype == "tool_call":
            run["tool_calls"].append({"name": ev.get("name"), "args": ev.get("args", {})})
        elif etype == "semantic_drift":
            run["semantic_drift"] = ev.get("results", [])
        elif etype == "gate_decision":
            run["gate_decision"] = {
                "intent": ev.get("intent"),
                "allowed_tools": ev.get("allowed_tools", []),
                "blocked": ev.get("blocked", False),
                "downgraded": ev.get("downgraded", False),
            }
        elif etype == "policy_decision":
            run["policy_decision"] = {"action": ev.get("action"), "reason": ev.get("reason")}
        elif etype == "arg_sanitize":
            run["arg_sanitize"] = {
                "name": ev.get("name"),
                "violations": ev.get("violations", []),
                "blocked": ev.get("blocked", False),
            }
        elif etype == "segments":
            run["segments"] = ev.get("segments", [])

    return run


def _load_calibration(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _format_score(s: float | None) -> str:
    if s is None:
        return "—"
    return f"{s:.3f}"


def _badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{text}</span>'


def _run_row(run: dict[str, Any]) -> str:
    status = "BLOCKED" if run["blocked"] else "OK"
    color = "#e53e3e" if run["blocked"] else "#38a169"
    mode_color = "#805ad5" if run["mode"] == "defended" else "#718096"

    drifts = run["semantic_drift"]
    max_drift = max((d.get("drift_score", 0.0) for d in drifts), default=0.0)
    flagged_any = any(d.get("flagged", False) for d in drifts)

    gate = run["gate_decision"]
    gate_str = ""
    if gate:
        intent = gate.get("intent", "?")
        down = "⬇" if gate.get("downgraded") else ""
        gate_str = f"{intent}{down}"

    policy = run["policy_decision"]
    policy_str = policy.get("action", "—") if policy else "—"

    return f"""
    <tr class="run-row" data-run-id="{run['run_id']}" onclick="showRun('{run['run_id']}')">
      <td><code>{run['run_id'][:10]}</code></td>
      <td>{run['attack_id'] or '—'}</td>
      <td>{_badge(run['mode'], mode_color)}</td>
      <td>{_badge(status, color)}</td>
      <td>{_format_score(max_drift)}{' 🚩' if flagged_any else ''}</td>
      <td>{gate_str or '—'}</td>
      <td>{policy_str}</td>
    </tr>"""


def _run_detail_json(runs: list[dict[str, Any]]) -> str:
    details: dict[str, Any] = {}
    for run in runs:
        details[run["run_id"]] = {
            "attack_id": run["attack_id"],
            "mode": run["mode"],
            "blocked": run["blocked"],
            "block_reason": run["block_reason"],
            "tool_calls": run["tool_calls"],
            "final_answer": run["final_answer"],
            "semantic_drift": run["semantic_drift"],
            "gate_decision": run["gate_decision"],
            "policy_decision": run["policy_decision"],
            "arg_sanitize": run["arg_sanitize"],
            "segments": [
                {
                    "source": s.get("source", "?"),
                    "trust_level": s.get("trust_level", "?"),
                    "content": (s.get("content") or "")[:500],
                }
                for s in run["segments"]
            ],
        }
    return json.dumps(details, indent=2)


def _calibration_section(cal: dict[str, Any] | None) -> str:
    if cal is None:
        return ""
    t = cal.get("chosen_threshold", "?")
    fpr = cal.get("fpr_at_threshold", "?")
    asr = cal.get("asr_at_threshold", "?")
    budget = cal.get("fpr_budget", "?")

    curve = cal.get("validation_curve", [])
    rows = ""
    for p in curve[::5]:
        marker = "←" if abs(p.get("threshold", 0) - t) < 1e-6 else ""
        rows += f"<tr><td>{p['threshold']:.3f}</td><td>{p['fpr']:.3f}</td><td>{p['tpr']:.3f}</td><td>{p['asr']:.3f}</td><td>{marker}</td></tr>"

    return f"""
    <section class="card">
      <h2>Day 14 — Threshold Calibration</h2>
      <div class="metric-grid">
        <div class="metric-box"><div class="metric-val">{t:.3f}</div><div class="metric-lbl">Chosen Threshold</div></div>
        <div class="metric-box"><div class="metric-val">{fpr:.3f}</div><div class="metric-lbl">FPR at Threshold</div></div>
        <div class="metric-box"><div class="metric-val">{asr:.3f}</div><div class="metric-lbl">ASR at Threshold</div></div>
        <div class="metric-box"><div class="metric-val">{budget:.3f}</div><div class="metric-lbl">FPR Budget</div></div>
      </div>
      <h3>Validation Curve (every 5th point)</h3>
      <table>
        <thead><tr><th>Threshold</th><th>FPR</th><th>TPR</th><th>ASR</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def generate_html_report(
    runs_dir: Path,
    calibration_path: Path | None = None,
) -> str:
    """Generate a self-contained HTML dashboard string."""
    run_files = sorted(runs_dir.glob("*.jsonl")) if runs_dir.exists() else []
    runs = [_load_run(p) for p in run_files]

    total = len(runs)
    blocked_count = sum(1 for r in runs if r["blocked"])
    defended = [r for r in runs if r["mode"] == "defended"]
    baseline = [r for r in runs if r["mode"] == "baseline"]

    def block_rate(subset: list[dict[str, Any]]) -> str:
        if not subset:
            return "—"
        return f"{sum(1 for r in subset if r['blocked']) / len(subset):.0%}"

    cal = _load_calibration(calibration_path)
    cal_section = _calibration_section(cal)

    rows = "".join(_run_row(r) for r in runs)
    run_details_js = _run_detail_json(runs)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLMFirewall — Evaluation Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f7fafc; color: #2d3748; font-size: 14px; }}
  header {{ background: #1a202c; color: white; padding: 16px 24px;
            display: flex; align-items: center; gap: 12px; }}
  header h1 {{ font-size: 20px; font-weight: 700; }}
  header .subtitle {{ color: #a0aec0; font-size: 13px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .card {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
           padding: 20px; margin-bottom: 20px; }}
  h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #1a202c; }}
  h3 {{ font-size: 14px; font-weight: 600; margin: 16px 0 8px; color: #4a5568; }}
  .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
                  gap: 12px; margin-bottom: 16px; }}
  .metric-box {{ background: #f7fafc; border-radius: 6px; padding: 16px; text-align: center; }}
  .metric-val {{ font-size: 28px; font-weight: 700; color: #2b6cb0; }}
  .metric-lbl {{ font-size: 12px; color: #718096; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #edf2f7; text-align: left; padding: 8px 10px;
        font-weight: 600; color: #4a5568; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  .run-row {{ cursor: pointer; transition: background 0.1s; }}
  .run-row:hover {{ background: #ebf8ff; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            color: white; font-size: 11px; font-weight: 600; }}
  code {{ font-family: 'SF Mono', Consolas, monospace; font-size: 12px;
          background: #edf2f7; padding: 1px 4px; border-radius: 3px; }}
  pre {{ background: #1a202c; color: #e2e8f0; padding: 14px; border-radius: 6px;
         overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }}
  .detail-panel {{ position: fixed; right: 0; top: 0; height: 100vh; width: 480px;
                   background: white; box-shadow: -4px 0 20px rgba(0,0,0,.15);
                   transform: translateX(100%); transition: transform 0.25s;
                   overflow-y: auto; padding: 20px; z-index: 100; }}
  .detail-panel.open {{ transform: translateX(0); }}
  .detail-panel h2 {{ font-size: 15px; margin-bottom: 12px; }}
  .close-btn {{ float: right; cursor: pointer; font-size: 20px; color: #a0aec0; line-height: 1; }}
  .seg-block {{ border-left: 3px solid #a0aec0; padding: 8px 12px; margin: 6px 0;
                border-radius: 0 4px 4px 0; background: #f7fafc; font-size: 12px; }}
  .seg-block.system {{ border-color: #3182ce; }}
  .seg-block.user {{ border-color: #38a169; }}
  .seg-block.retrieved_doc {{ border-color: #d69e2e; }}
  .seg-block.tool_output {{ border-color: #9f7aea; }}
  .flag-row {{ display: flex; gap: 8px; align-items: center; margin: 4px 0; font-size: 12px; }}
  .flag-label {{ font-weight: 600; color: #4a5568; width: 130px; flex-shrink: 0; }}
  .flag-val {{ color: #2d3748; }}
  .overlay {{ position: fixed; inset: 0; background: rgba(0,0,0,0.3);
              display: none; z-index: 99; }}
  .overlay.show {{ display: block; }}
</style>
</head>
<body>

<header>
  <div>
    <h1>🔥 LLMFirewall</h1>
    <div class="subtitle">Prompt Injection Defense Evaluation Dashboard</div>
  </div>
</header>

<div class="container">

  <!-- Summary metrics -->
  <div class="card">
    <h2>Summary</h2>
    <div class="metric-grid">
      <div class="metric-box"><div class="metric-val">{total}</div><div class="metric-lbl">Total Runs</div></div>
      <div class="metric-box"><div class="metric-val">{blocked_count}</div><div class="metric-lbl">Blocked</div></div>
      <div class="metric-box"><div class="metric-val">{len(defended)}</div><div class="metric-lbl">Defended Runs</div></div>
      <div class="metric-box"><div class="metric-val">{len(baseline)}</div><div class="metric-lbl">Baseline Runs</div></div>
      <div class="metric-box"><div class="metric-val">{block_rate(defended)}</div><div class="metric-lbl">Defended Block Rate</div></div>
      <div class="metric-box"><div class="metric-val">{block_rate(baseline)}</div><div class="metric-lbl">Baseline Block Rate</div></div>
    </div>
  </div>

  {cal_section}

  <!-- Run list -->
  <div class="card">
    <h2>Runs <span style="font-weight:400;color:#718096;font-size:13px">— click a row to inspect</span></h2>
    <table>
      <thead>
        <tr>
          <th>Run ID</th><th>Attack ID</th><th>Mode</th><th>Status</th>
          <th>Max Drift</th><th>Gate Intent</th><th>Policy</th>
        </tr>
      </thead>
      <tbody>
        {rows if rows else '<tr><td colspan="7" style="text-align:center;color:#a0aec0;padding:24px">No runs found in runs/ directory</td></tr>'}
      </tbody>
    </table>
  </div>

</div>

<!-- Detail panel (slide-in) -->
<div class="overlay" id="overlay" onclick="closePanel()"></div>
<div class="detail-panel" id="detail-panel">
  <span class="close-btn" onclick="closePanel()">✕</span>
  <h2 id="detail-title">Run Details</h2>
  <div id="detail-content"></div>
</div>

<script>
const RUN_DATA = {run_details_js};

function showRun(runId) {{
  const run = RUN_DATA[runId];
  if (!run) return;

  document.getElementById('detail-title').textContent = 'Run: ' + runId.slice(0, 10) + ' (' + run.mode + ')';

  let html = '';

  // Status
  const statusColor = run.blocked ? '#e53e3e' : '#38a169';
  html += '<div class="flag-row"><span class="flag-label">Status</span>';
  html += '<span class="badge" style="background:' + statusColor + '">' + (run.blocked ? 'BLOCKED' : 'OK') + '</span></div>';
  if (run.block_reason) {{
    html += '<div class="flag-row"><span class="flag-label">Block reason</span><span class="flag-val">' + esc(run.block_reason) + '</span></div>';
  }}

  // Detector flags
  html += '<h3>Detector Signals</h3>';
  if (run.semantic_drift && run.semantic_drift.length) {{
    run.semantic_drift.forEach(function(d) {{
      const flagged = d.flagged ? '🚩 FLAGGED' : 'ok';
      html += '<div class="flag-row"><span class="flag-label">Semantic drift (' + esc(d.source) + ')</span>';
      html += '<span class="flag-val">drift=' + (d.drift_score||0).toFixed(3) + ' ' + flagged + '</span></div>';
    }});
  }} else {{
    html += '<div class="flag-row"><span class="flag-val" style="color:#a0aec0">No semantic drift data</span></div>';
  }}

  if (run.gate_decision) {{
    const g = run.gate_decision;
    html += '<div class="flag-row"><span class="flag-label">Tool gate</span>';
    html += '<span class="flag-val">intent=' + esc(g.intent||'?') + (g.downgraded?' ⬇downgraded':'') + (g.blocked?' 🚫blocked':'') + '</span></div>';
    html += '<div class="flag-row"><span class="flag-label">Allowed tools</span>';
    html += '<span class="flag-val">' + (g.allowed_tools||[]).join(', ') + '</span></div>';
  }}

  if (run.policy_decision) {{
    const p = run.policy_decision;
    html += '<div class="flag-row"><span class="flag-label">Policy engine</span>';
    html += '<span class="flag-val">' + esc(p.action||'?') + ' — ' + esc(p.reason||'') + '</span></div>';
  }}

  if (run.arg_sanitize) {{
    const a = run.arg_sanitize;
    html += '<div class="flag-row"><span class="flag-label">Arg sanitizer (' + esc(a.name||'?') + ')</span>';
    html += '<span class="flag-val">' + (a.blocked ? '🚫 blocked' : 'ok') + (a.violations&&a.violations.length ? ' — ' + esc(a.violations.join(', ')) : '') + '</span></div>';
  }}

  // Prompt segments
  if (run.segments && run.segments.length) {{
    html += '<h3>Prompt Segments</h3>';
    run.segments.forEach(function(s) {{
      const cls = s.source || 'unknown';
      html += '<div class="seg-block ' + cls + '">';
      html += '<strong>[' + esc(s.source) + ' / ' + esc(s.trust_level) + ']</strong><br>';
      html += '<span>' + esc((s.content||'').slice(0, 300)) + (s.content && s.content.length > 300 ? '…' : '') + '</span>';
      html += '</div>';
    }});
  }}

  // Tool calls + final answer
  if (run.tool_calls && run.tool_calls.length) {{
    html += '<h3>Tool Calls</h3>';
    run.tool_calls.forEach(function(tc) {{
      html += '<code>' + esc(tc.name) + '(' + esc(JSON.stringify(tc.args)) + ')</code><br>';
    }});
  }}

  if (run.final_answer) {{
    html += '<h3>Final Answer</h3><pre>' + esc(run.final_answer.slice(0, 400)) + '</pre>';
  }}

  document.getElementById('detail-content').innerHTML = html;
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('overlay').classList.add('show');
}}

function closePanel() {{
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('overlay').classList.remove('show');
}}

function esc(s) {{
  if (s === undefined || s === null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
</script>
</body>
</html>"""
