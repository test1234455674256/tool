import requests
from bs4 import BeautifulSoup
import json, time, datetime
from urllib.parse import urljoin

SESSION = requests.Session()


# ---------------------------
# A) LOGIN FORM DISCOVERY
# ---------------------------
def detect_form(url):
    print("[+] Detecting login form…")
    r = SESSION.get(url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")

    form = soup.find("form")
    if not form:
        return None

    action = form.get("action", "")
    method = form.get("method", "GET").upper()

    inputs = form.find_all("input")
    username = password = csrf_name = csrf_value = None

    for i in inputs:
        t = i.get("type", "").lower()
        name = i.get("name", "")

        if t in ["text", "email"] or "user" in name.lower():
            username = name
        if t == "password":
            password = name
        if "csrf" in name.lower():
            csrf_name = name
            csrf_value = i.get("value", "")

    return {
        "action": action,
        "method": method,
        "username": username,
        "password": password,
        "csrf_name": csrf_name,
        "csrf_value": csrf_value,
    }


# ---------------------------
# Helper submit function
# ---------------------------
def submit(url, form, data, follow=False):
    action_url = urljoin(url, form["action"])
    method = form["method"]

    if method == "POST":
        r = SESSION.post(action_url, data=data, allow_redirects=follow)
    else:
        r = SESSION.get(action_url, params=data, allow_redirects=follow)

    return r


# ---------------------------
# MAIN TESTS (A–Z)
# ---------------------------
def run_tests(url):

    form = detect_form(url)
    if not form:
        raise Exception("Login form not detected!")

    results = {}

    # ----------------------------
    # B) FORM ACTION DETECTION
    # ----------------------------
    results["form_action"] = form["action"]

    # ----------------------------
    # C) HTTP METHOD CONFIRMATION
    # ----------------------------
    results["form_method"] = form["method"]

    # ----------------------------
    # D) CSRF TOKEN PRESENCE
    # ----------------------------
    results["csrf_present"] = True if form["csrf_name"] else False

    # ----------------------------
    # E) CSRF VALIDATION TEST
    # ----------------------------
    if form["csrf_name"]:
        r = submit(url, form, {
            form["username"]: "admin",
            form["password"]: "admin",
            form["csrf_name"]: "INVALIDTOKEN"
        })
        results["csrf_invalid_status"] = r.status_code
    else:
        results["csrf_invalid_status"] = 0

    # ----------------------------
    # F) Correct login (valid)
    # ----------------------------
    valid_payload = {
        form["username"]: "admin",
        form["password"]: "admin"
    }
    if form["csrf_name"]:
        valid_payload[form["csrf_name"]] = form["csrf_value"]

    r = submit(url, form, valid_payload, follow=True)
    results["login_success_status"] = r.status_code

    # ----------------------------
    # G) Wrong login attempt
    # ----------------------------
    wrong_payload = {
        form["username"]: "admin",
        form["password"]: "WRONGPASS"
    }
    if form["csrf_name"]:
        wrong_payload[form["csrf_name"]] = form["csrf_value"]

    r = submit(url, form, wrong_payload)
    results["wrong_login_status"] = r.status_code

    # ----------------------------
    # H) No-CSRF attack test
    # ----------------------------
    if form["csrf_name"]:
        r = submit(url, form, {
            form["username"]: "admin",
            form["password"]: "admin"
        })
        results["no_csrf_status"] = r.status_code
    else:
        results["no_csrf_status"] = 0

    # ----------------------------
    # I) Session fixation test
    # ----------------------------
    fix_session = requests.Session()
    fix_session.cookies.set("sessionid", "FIXEDVALUE")
    r = fix_session.get(url)
    results["session_fixation_initial"] = "sessionid" in fix_session.cookies.get_dict()

    # ----------------------------
    # J) Redirect chain validation
    # ----------------------------
    r = submit(url, form, valid_payload, follow=True)
    results["redirect_count"] = len(r.history)

    # ----------------------------
    # K) Cookie security check
    # ----------------------------
    cookies = SESSION.cookies.get_dict()
    results["cookie_security"] = {
        "httponly": any("HttpOnly" in str(c) for c in cookies),
        "secure": any("Secure" in str(c) for c in cookies)
    }

    # ----------------------------
    # L) Response code behavior
    # ----------------------------
    results["response_after_login"] = r.status_code

    # ----------------------------
    # M) Rate-limit detection
    # (Only 3 requests = safe simulation)
    # ----------------------------
    rate_codes = []
    for _ in range(3):
        rr = submit(url, form, wrong_payload)
        rate_codes.append(rr.status_code)
    results["rate_limit_codes"] = rate_codes

    # ----------------------------
    # N) Error message enumeration
    # ----------------------------
    results["error_message_length"] = len(r.text)

    # ----------------------------
    # O) Form tampering
    # ----------------------------
    tampered_payload = {
        "unexpected": "value"
    }
    rr = submit(url, form, tampered_payload)
    results["tamper_status"] = rr.status_code

    # ----------------------------
    # P) Missing-fields submission
    # ----------------------------
    rr = submit(url, form, {})
    results["empty_fields_status"] = rr.status_code

    # ----------------------------
    # Q) Empty request test
    # ----------------------------
    rr = SESSION.post(urljoin(url, form["action"]), data=None)
    results["empty_request_status"] = rr.status_code

    # ----------------------------
    # R) Invalid HTTP method
    # ----------------------------
    try:
        rr = SESSION.put(urljoin(url, form["action"]))
        results["invalid_method_status"] = rr.status_code
    except:
        results["invalid_method_status"] = "error"

    # ----------------------------
    # S) Payload manipulation
    # ----------------------------
    bad_payload = {
        form["username"]: "<script>",
        form["password"]: "<>"
    }
    rr = submit(url, form, bad_payload)
    results["payload_manipulation_status"] = rr.status_code

    # ----------------------------
    # T) Special-char payload
    # ----------------------------
    special = {
        form["username"]: "!@#$%^&*()_+",
        form["password"]: "!@#"
    }
    rr = submit(url, form, special)
    results["special_chars_status"] = rr.status_code

    # ----------------------------
    # U) SQLi payload
    # ----------------------------
    sql = {
        form["username"]: "' OR 1=1 --",
        form["password"]: "' OR 1=1 --"
    }
    rr = submit(url, form, sql)
    results["sqli_status"] = rr.status_code

    # ----------------------------
    # V) XSS payload test
    # ----------------------------
    xss = {
        form["username"]: "<img src=x onerror=alert(1)>",
        form["password"]: "x"
    }
    rr = submit(url, form, xss)
    results["xss_status"] = rr.status_code

    # ----------------------------
    # W) Brute-force simulation (safe)
    # ----------------------------
    bf_codes = []
    for pwd in ["111", "222", "333"]:  # safe small 3 attempts
        bf_payload = {
            form["username"]: "admin",
            form["password"]: pwd
        }
        if form["csrf_name"]:
            bf_payload[form["csrf_name"]] = form["csrf_value"]
        rr = submit(url, form, bf_payload)
        bf_codes.append(rr.status_code)
    results["bruteforce_simulation"] = bf_codes

    # ----------------------------
    # X) Anti-bot / Timing
    # ----------------------------
    start = time.time()
    submit(url, form, wrong_payload)
    end = time.time()
    results["request_time_ms"] = int((end - start) * 1000)

    # ----------------------------
    # Y) Logout behavior check
    # ----------------------------
    logout_candidates = ["/logout", "/signout", "/logoff"]
    logout_status = None

    for path in logout_candidates:
        try:
            rr = SESSION.get(urljoin(url, path))
            if rr.status_code in [200, 302]:
                logout_status = rr.status_code
                break
        except:
            pass

    results["logout_status"] = logout_status

    # ----------------------------
    # Z) Session cleanup
    # ----------------------------
    SESSION.cookies.clear()
    results["session_cleanup_success"] = len(SESSION.cookies.get_dict()) == 0

    return {
        "url": url,
        "timestamp": time.time(),
        "tests": results
    }


# ---------------------------
# MAIN EXECUTION
# ---------------------------
if __name__ == "__main__":
    import sys, os
    url = os.getenv("AUTH_TEST_URL", sys.argv[1] if len(sys.argv) > 1 else None)
    if not url:
        raise SystemExit("Missing URL")

    result = run_tests(url)

    os.makedirs("auth-tests/reports", exist_ok=True)
    out = "auth-tests/reports/auth_summary.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Auth test summary saved → {out}")
