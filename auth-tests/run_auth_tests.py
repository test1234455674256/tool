import requests
from bs4 import BeautifulSoup
import json, time, datetime
from urllib.parse import urljoin

def detect_form(url):
    """Detect login form fields + csrf."""
    print("[+] Detecting login form…")
    r = requests.get(url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")

    form = soup.find("form")
    if not form:
        return None

    action = form.get("action", "")
    method = form.get("method", "GET").upper()

    inputs = form.find_all("input")
    username, password, csrf_name, csrf_val = None, None, None, None

    for i in inputs:
        t = i.get("type", "").lower()
        name = i.get("name", "")
        if t == "text" or "user" in name.lower():
            username = name
        if t == "password":
            password = name
        if "csrf" in name.lower():
            csrf_name = name
            csrf_val = i.get("value", "")

    return {
        "action": action,
        "method": method,
        "username": username,
        "password": password,
        "csrf_name": csrf_name,
        "csrf_value": csrf_val,
    }


def submit(url, form, data):
    action_url = urljoin(url, form["action"])
    method = form["method"]

    if method == "POST":
        r = requests.post(action_url, data=data, allow_redirects=False)
    else:
        r = requests.get(action_url, params=data, allow_redirects=False)
    return r.status_code


def run_tests(url):

    form = detect_form(url)
    if not form:
        raise Exception("Login form not detected!")

    print("[+] Running authentication test suite (A–Z)…")
    
    tests = {}

    # A) Valid login
    tests["valid_login_status"] = submit(url, form, {
        form["username"]: "admin",
        form["password"]: "admin",
        form["csrf_name"]: form["csrf_value"]
    }) if form["csrf_name"] else submit(url, form, {
        form["username"]: "admin",
        form["password"]: "admin"
    })

    # B) Wrong login
    tests["wrong_login_status"] = submit(url, form, {
        form["username"]: "admin",
        form["password"]: "WRONG"
    })

    # C) Missing CSRF
    if form["csrf_name"]:
        tests["no_csrf_status"] = submit(url, form, {
            form["username"]: "admin",
            form["password"]: "admin"
        })
    else:
        tests["no_csrf_status"] = 0

    # D–Z dummy structure (expandable)
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        tests[f"test_{letter}"] = "pending"

    return {
        "url": url,
        "timestamp": time.time(),
        "detected": {
            "action": form["action"],
            "method": form["method"],
            "username_field": form["username"],
            "password_field": form["password"],
            "csrf_name": form["csrf_name"],
            "csrf_value_len": len(form["csrf_value"]) if form["csrf_value"] else 0
        },
        "tests": tests
    }


if __name__ == "__main__":
    import sys, os
    url = os.getenv("AUTH_TEST_URL", sys.argv[1] if len(sys.argv) > 1 else None)
    if not url:
        raise SystemExit("Missing URL")

    result = run_tests(url)

    # Save JSON
    os.makedirs("auth-tests/reports", exist_ok=True)
    out = "auth-tests/reports/auth_summary.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Auth test summary saved → {out}")
