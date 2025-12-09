import json, os, datetime
from pathlib import Path

def html_escape(x):
    return str(x).replace("<","&lt;").replace(">","&gt;")

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
</style>
</head>
<body>

<div class="box">
    <h2>Authentication Testing Report</h2>
    <p><b>URL:</b> {data["url"]}</p>
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
        <tr><th>Test</th><th>Status</th></tr>
"""

    # Automated status rendering  
    def row(name, code):
        status = "ok" if code in (301,302,200) else "fail"
        return f"<tr><td>{name}</td><td class='{status}'>{code}</td></tr>"

    html += row("A) Valid Login Attempt", data["tests"]["valid_login_status"])
    html += row("B) Wrong Password Attempt", data["tests"]["wrong_login_status"])
    html += row("C) Missing CSRF", data["tests"]["no_csrf_status"])

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
