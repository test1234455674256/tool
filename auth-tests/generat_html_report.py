import json, os, datetime
from pathlib import Path

def html_escape(x):
    return str(x).replace("<","&lt;").replace(">","&gt;")

def status_class(value):
    """Smart status evaluator for any test output."""
    if isinstance(value, bool):
        return "ok" if value else "fail"

    if isinstance(value, list):
        # ok if at least one is 200/302
        return "ok" if any(v in (200, 302) for v in value) else "fail"

    try:
        v = int(value)
        return "ok" if v in (200, 302) else "warn" if v in (400, 401, 403) else "fail"
    except:
        return "fail"

def generate_html(infile, outfile):
    with open(infile) as f:
        data = json.load(f)

    ts = datetime.datetime.utcfromtimestamp(data["timestamp"]).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""
<html>
<head>
<title>Authentication Report — {data['url']}</title>
<style>
    body {{ font-family: Arial; background: #f5f5f5; padding: 20px; }}
    .box {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 8px; border-bottom: 1px solid #ccc; font-size: 14px; }}
    h2 {{ margin-top: 0; }}
    .ok {{ color: green; font-weight: bold; }}
    .fail {{ color: red; font-weight: bold; }}
    .warn {{ color: orange; font-weight: bold; }}
    pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head>
<body>

<div class="box">
    <h2>Authentication Testing Report</h2>
    <p><b>URL:</b> {html_escape(data["url"])}</p>
    <p><b>Generated:</b> {ts}</p>
</div>

<div class="box">
    <h2>Detection Summary</h2>
    <table>
        <tr><td>Form Action</td><td>{html_escape(data["detected"]["action"])}</td></tr>
        <tr><td>Method</td><td>{data["detected"]["method"]}</td></tr>
        <tr><td>Username Field</td><td>{data["detected"]["username_field"]}</td></tr>
        <tr><td>Password Field</td><td>{data["detected"]["password_field"]}</td></tr>
        <tr><td>CSRF Token Name</td><td>{data["detected"]["csrf_name"]}</td></tr>
        <tr><td>CSRF Value Length</td><td>{data["detected"]["csrf_value_len"]}</td></tr>
    </table>
</div>

<div class="box">
    <h2>Test Cases (A–Z)</h2>
    <table>
        <tr><th>Test</th><th>Value</th><th>Status</th></tr>
"""

    # Dynamically list all test items
    for key, value in data["tests"].items():
        label = key.replace("_", " ").title()
        cls = status_class(value)
        html += f"<tr><td>{label}</td><td>{html_escape(value)}</td><td class='{cls}'>{cls.upper()}</td></tr>"

    html += """
    </table>
</div>

<div class="box">
    <h2>Full Raw JSON</h2>
    <pre style="background:#222; color:#0f0; padding:15px; border-radius:6px; font-size:13px;">""" + \
        html_escape(json.dumps(data, indent=2)) + "</pre></div>"

    html += "</body></html>"

    with open(outfile, "w") as f:
        f.write(html)

    print(f"[+] HTML report saved at: {outfile}")


if __name__ == "__main__":
    Path("auth-tests/reports").mkdir(parents=True, exist_ok=True)
    generate_html("auth-tests/reports/auth_summary.json", "auth-tests/reports/auth_report.html")
