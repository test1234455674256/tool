import json
import datetime
from pathlib import Path
from html import escape as html_escape


def safe_get(data, key, default="N/A"):
    """Safely extract nested keys."""
    return data.get(key, default) if isinstance(data, dict) else default


def safe_timestamp(ts):
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return "N/A"


def generate_html(json_path, output_path):
    json_path = Path(json_path)
    output_path = Path(output_path)

    if not json_path.exists():
        raise FileNotFoundError(f"Input JSON not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Safe wrapper to avoid KeyError
    detected = safe_get(data, "detected", {})

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Authentication Scan Report</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background: #f2f2f2; }}
</style>
</head>
<body>

<h2>Authentication Summary Report</h2>

<table>
    <tr><th>Field</th><th>Result</th></tr>
    <tr><td>URL</td><td>{html_escape(safe_get(data, "url"))}</td></tr>
    <tr><td>Detected Method</td><td>{html_escape(safe_get(detected, "method"))}</td></tr>
    <tr><td>Form Action</td><td>{html_escape(safe_get(detected, "action"))}</td></tr>
    <tr><td>Timestamp</td><td>{safe_timestamp(safe_get(data, "timestamp", 0))}</td></tr>
</table>

<h3>Additional Details</h3>
<pre>{html_escape(json.dumps(data, indent=4))}</pre>

</body>
</html>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")


if __name__ == "__main__":
    generate_html("auth-tests/reports/auth_summary.json",
                  "auth-tests/reports/auth_report.html")
