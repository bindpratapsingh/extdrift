"""Render one analysis record into a short, self-contained HTML briefing.

The page the demo shows is for watching the analysis happen; this is the artefact you
keep afterwards. It reads a run's ``report.json`` (which carries a ``briefing`` block
written by :func:`demo.analysis.build_briefing`) and produces one printable HTML file
with inline styles and an inline SVG chart - no external assets - so it prints straight
to PDF from any browser and survives being emailed around.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

VERDICT_FILL = {
    "malicious": "#8c1420", "suspicious": "#8a6214",
    "benign": "#1d5137", "nochange": "#3d4349",
}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _chart_svg(series: list[dict]) -> str:
    """A horizontal grouped bar chart: version N and version N+1 for each feature that
    moved, on one shared count axis. Hand-rolled SVG so the report needs no libraries."""
    if not series:
        return "<p class='muted'>No counted behaviour to chart for this pair.</p>"
    row_h, bar_h, gap, left, top, width = 46, 15, 6, 210, 16, 760
    plot_w = width - left - 24
    hi = max(1.0, max(max(s["v1"], s["v2"]) for s in series))
    height = top + len(series) * row_h + 12

    def bar(y, value, cls, fill):
        w = (value / hi) * plot_w
        label_x = left + w + 6
        return (f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar_h}" fill="{fill}"/>'
                f'<text x="{label_x:.1f}" y="{y + bar_h - 3}" class="val">{value:g}</text>')

    rows = []
    for i, s in enumerate(series):
        y = top + i * row_h
        rows.append(
            f'<text x="{left - 10}" y="{y + bar_h}" class="cat">{_esc(s["label"])}</text>'
            + bar(y, s["v1"], "v1", "#9aa3ad")
            + bar(y + bar_h + gap, s["v2"], "v2", "#1b4e8a"))
    legend = (f'<rect x="{left}" y="0" width="11" height="11" fill="#9aa3ad"/>'
              f'<text x="{left + 16}" y="9" class="leg">version N</text>'
              f'<rect x="{left + 110}" y="0" width="11" height="11" fill="#1b4e8a"/>'
              f'<text x="{left + 126}" y="9" class="leg">version N+1</text>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" '
            f'style="max-width:{width}px" role="img" aria-label="behaviour counts by version">'
            f'<style>.cat{{font:12px Arial;fill:#111;text-anchor:end}}'
            f'.val{{font:11px Consolas,monospace;fill:#444}}'
            f'.leg{{font:11px Arial;fill:#444}}</style>'
            f'{legend}{"".join(rows)}</svg>')


def render_report_html(record: dict) -> str:
    b = record.get("briefing")
    if not b:
        return "<!doctype html><title>report</title><p>This run has no briefing.</p>"

    ext = b.get("extension", {})
    fill = VERDICT_FILL.get(b.get("class", ""), "#3d4349")
    generated = record.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")

    doing = "".join("<li>%s</li>" % _esc(x) for x in b.get("doing", []))
    capability = "".join("<li>%s</li>" % _esc(x) for x in b.get("capability_change", []))
    confidence = "".join("<li>%s</li>" % _esc(x) for x in b.get("confidence", []))

    if b.get("indicators"):
        rows = "".join(
            "<tr><td>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(i.get("name")), _esc("%.2f" % i["weight"]) if i.get("weight") is not None
                else "", _esc(i.get("provenance")), _esc(i.get("evidence")))
            for i in b["indicators"])
        indicators = ("<table><thead><tr><th>Indicator</th><th>Weight</th>"
                      "<th>Grounded in</th><th>What triggered it</th></tr></thead>"
                      "<tbody>%s</tbody></table>" % rows)
    else:
        indicators = "<p class='muted'>No heuristic fired. Nothing matched a known-dangerous pattern.</p>"

    scores = " &nbsp; ".join("%s <b>%.3f</b>" % (_esc(k), v)
                             for k, v in b.get("scores", {}).items())
    proven = ('<p class="proven">Exfiltration was <b>observed</b>: the sandbox collector '
              'logged the upload. This is ground truth, not an inference.</p>'
              if b.get("collector_proven") else "")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>extdrift report - {_esc(ext.get('name'))}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.5 Arial, Helvetica, sans-serif; color: #111; margin: 0;
          background: #f4f4f5; }}
  .sheet {{ max-width: 860px; margin: 24px auto; background: #fff; padding: 34px 40px;
            border: 1px solid #d5d5d8; }}
  h1 {{ font-size: 20px; margin: 0 0 2px; }}
  h2 {{ font-size: 13px; letter-spacing: .06em; text-transform: uppercase; color: #555;
        border-bottom: 1px solid #e2e2e5; padding-bottom: 5px; margin: 26px 0 12px; }}
  .sub {{ color: #666; font-size: 13px; margin: 0 0 18px; }}
  .verdict {{ display: flex; align-items: center; gap: 16px; color: #fff;
              background: {fill}; padding: 14px 18px; margin: 4px 0 6px; }}
  .verdict .label {{ font-size: 22px; font-weight: 700; letter-spacing: .04em; }}
  .verdict .headline {{ font-size: 14px; opacity: .95; }}
  ul {{ margin: 6px 0; padding-left: 20px; }} li {{ margin: 3px 0; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 9px; border-bottom: 1px solid #e6e6e8;
            vertical-align: top; }}
  th {{ font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #555; }}
  .mono {{ font-family: Consolas, "Courier New", monospace; }}
  .muted {{ color: #777; }}
  .scores {{ font-size: 14px; }}
  .proven {{ background: #fbf1f2; border-left: 3px solid #8c1420; padding: 8px 12px;
             margin: 10px 0; }}
  .foot {{ margin-top: 28px; color: #888; font-size: 11.5px; border-top: 1px solid #e2e2e5;
           padding-top: 10px; }}
  @media print {{ body {{ background: #fff; }} .sheet {{ border: 0; margin: 0; max-width: none; }} }}
</style></head><body><div class="sheet">
  <h1>extdrift &mdash; behavioural-diff report</h1>
  <p class="sub">{_esc(ext.get('name'))} &nbsp;&middot;&nbsp; version {_esc(ext.get('v1'))}
     &rarr; {_esc(ext.get('v2'))} &nbsp;&middot;&nbsp; MV{_esc(ext.get('manifest_version'))}
     &nbsp;&middot;&nbsp; generated {_esc(generated)}</p>

  <div class="verdict"><span class="label">{_esc(b.get('verdict'))}</span>
    <span class="headline">{_esc(b.get('headline'))}</span></div>
  <p>{_esc(b.get('summary'))}</p>
  {proven}

  <h2>What the update is doing</h2>
  <ul>{doing}</ul>

  <h2>Behaviour by version</h2>
  {_chart_svg(b.get('chart', []))}

  <h2>Indicators behind the verdict</h2>
  {indicators}

  <h2>Declared capability change</h2>
  <ul>{capability}</ul>

  <h2>Scores &amp; confidence</h2>
  <p class="scores">{scores}</p>
  <ul>{confidence}</ul>

  <p class="foot">Every version ran in a sealed, offline sandbox; no packet left the
    machine. "Score the change, not the extension." &mdash; extdrift, CSD493.</p>
</div></body></html>"""
