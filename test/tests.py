#!/usr/bin/env python3
"""
Authentication automation testing (Playwright, sync API).

Covers:
 - valid login
 - invalid login
 - lockout simulation (safe, respects max attempts)
 - CSRF token discovery on login page
 - JWT / token checks (cookies + localStorage)
 - remember-me cookie check
 - logout -> session invalidation check
 - open-redirect test for returnUrl
 - simple JSON report output
"""

import json
import time
import re
import os
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
import jwt  # pyjwt
import requests

# --- Utility functions ---
def load_creds(path="creds.json"):
    with open(path, "r") as f:
        return json.load(f)

def save_report(report, path="report.json"):
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {path}")

def find_csrf_token(page):
    # look for common hidden token inputs
    try:
        # search hidden inputs with token-like names
        elems = page.query_selector_all("input[type=hidden]")
        for e in elems:
            name = e.get_attribute("name") or ""
            if re.search(r"csrf|token|auth", name, re.I):
                return {"name": name, "value": e.get_attribute("value")}
        # meta tags
        metas = page.query_selector_all("meta")
        for m in metas:
            name = m.get_attribute("name") or ""
            if re.search(r"csrf|token", name, re.I):
                return {"meta_name": name, "content": m.get_attribute("content")}
    except Exception:
        pass
    return None

def decode_jwt_if_possible(token_value):
    try:
        # try decode without verification
        decoded = jwt.decode(token_value, options={"verify_signature": False})
        return decoded
    except Exception:
        return None

def pretty_cookie_info(c):
    return {
        "name": c["name"],
        "value_preview": c["value"][:50] + ("..." if len(c["value"])>50 else ""),
        "expires": c.get("expires"),
        "httpOnly": c.get("httpOnly"),
        "secure": c.get("secure"),
        "domain": c.get("domain"),
        "path": c.get("path")
    }

# --- Core tests ---
def test_valid_login(page, base_url, creds):
    result = {"ok": False, "notes": []}
    page.goto(base_url, wait_until="domcontentloaded")
    time.sleep(0.5)

    # heuristics for username/password fields and submit
    # adjust selectors if your app uses different names
    selectors = [
        ("input[name=email]", "input[name=password]", "button[type=submit]"),
        ("input[type=email]", "input[type=password]", "button[type=submit]"),
        ("input[name=username]", "input[name=password]", "button[type=submit]"),
        ("input[name=login]", "input[name=pass]", "button[type=submit]"),
    ]

    used = None
    for u_sel, p_sel, s_sel in selectors:
        try:
            if page.query_selector(u_sel) and page.query_selector(p_sel):
                used = (u_sel, p_sel, s_sel)
                break
        except Exception:
            continue
    if not used:
        result["notes"].append("Could not auto-detect username/password fields. You may need to update selectors.")
        return result

    u_sel, p_sel, s_sel = used
    page.fill(u_sel, creds["username"])
    page.fill(p_sel, creds["password"])
    # attempt to tick remember me if present
    try:
        if page.query_selector("input[name=remember]"):
            page.check("input[name=remember]")
            result["notes"].append("Remember-me checkbox found and checked.")
    except Exception:
        pass

    # capture any CSRF token we discovered
    csrf = find_csrf_token(page)
    if csrf:
        result["csrf"] = csrf

    # submit
    try:
        page.click(s_sel)
    except Exception:
        # fallback: press enter in password field
        page.press(p_sel, "Enter")

    # wait for navigation or change
    try:
        page.wait_for_load_state("networkidle", timeout=5000)
    except PWTimeout:
        pass

    # heuristics: logged-in if URL changed away from login or protected element visible
    current_url = page.url
    result["url_after_login"] = current_url
    # check for common logout/profile elements
    logged_in_indicators = ["logout", "sign out", "/account", "profile"]
    try:
        page_text = page.content().lower()
    except Exception:
        page_text = ""
    if any(k in current_url.lower() for k in logged_in_indicators) or any(k in page_text for k in logged_in_indicators):
        result["ok"] = True
    else:
        # also check cookies/localStorage for tokens
        cookies = page.context.cookies()
        token_candidates = []
        for c in cookies:
            if re.search(r"jwt|token|session", c["name"], re.I):
                token_candidates.append(pretty_cookie_info(c))
        result["cookies_token_candidates"] = token_candidates

        # localStorage check
        try:
            ls = page.evaluate("() => { return Object.keys(window.localStorage || {}).map(k=>({k:k,v:window.localStorage.getItem(k).slice(0,200)})) }")
            result["localStorage_keys_preview"] = ls
            for k,v in ls:
                if re.search(r"jwt|token|access", k, re.I) or (isinstance(v,str) and re.search(r"eyJ", v)):
                    result.setdefault("localStorage_token_detected", []).append(k)
        except Exception:
            pass

    # record cookies for later
    result["cookies"] = [pretty_cookie_info(c) for c in page.context.cookies()]

    # try decode JWTs found in cookies/localStorage
    decoded = []
    for c in page.context.cookies():
        if re.search(r"jwt|token|access|id", c["name"], re.I) and re.get("eyJ", ""):
            candidate = c["value"]
            dec = decode_jwt_if_possible(candidate)
            if dec:
                decoded.append({"cookie": c["name"], "decoded": dec})
    # localStorage tokens may already been listed; try to inspect values directly more safely
    try:
        for k in page.evaluate("() => Object.keys(window.localStorage || {})"):
            v = page.evaluate(f"() => window.localStorage.getItem({json.dumps(k)})")
            if isinstance(v,str) and v.startswith("eyJ"):
                dec = decode_jwt_if_possible(v)
                if dec:
                    decoded.append({"localStorage": k, "decoded": dec})
    except Exception:
        pass

    if decoded:
        result["jwt_decoded_samples"] = decoded

    return result

def test_invalid_login(page, base_url, invalid_creds):
    result = {"ok": False, "notes": []}
    page.goto(base_url, wait_until="domcontentloaded")
    time.sleep(0.5)

    # try auto-detect similar to valid test
    selectors = [
        ("input[name=email]", "input[name=password]", "button[type=submit]"),
        ("input[type=email]", "input[type=password]", "button[type=submit]"),
        ("input[name=username]", "input[name=password]", "button[type=submit]"),
    ]
    used = None
    for u_sel, p_sel, s_sel in selectors:
        try:
            if page.query_selector(u_sel) and page.query_selector(p_sel):
                used = (u_sel, p_sel, s_sel)
                break
        except Exception:
            continue
    if not used:
        result["notes"].append("Could not auto-detect username/password fields.")
        return result

    u_sel, p_sel, s_sel = used
    page.fill(u_sel, invalid_creds["username"])
    page.fill(p_sel, invalid_creds["password"])
    try:
        page.click(s_sel)
    except Exception:
        page.press(p_sel, "Enter")

    # wait a bit and inspect for error messages
    time.sleep(1.0)
    page_text = ""
    try:
        page_text = page.content().lower()
    except Exception:
        pass

    common_error_phrases = ["invalid", "incorrect", "failed", "does not match", "no user", "locked"]
    found = [p for p in common_error_phrases if p in page_text]
    result["error_messages_detected"] = list(set(found))
    result["ok"] = len(found) > 0
    return result

def test_lockout_simulation(page, base_url, invalid_creds, max_attempts=5):
    # Note: this performs limited attempts and stops — do NOT brute force beyond allowed.
    result = {"attempts": [], "observed_lockout": False}
    page.goto(base_url, wait_until="domcontentloaded")
    for i in range(max_attempts):
        try:
            page.reload()
            time.sleep(0.3)
            # fill fields (same detection)
            u_sel = "input[name=email]" if page.query_selector("input[name=email]") else "input[name=username]" if page.query_selector("input[name=username]") else None
            p_sel = "input[name=password]" if page.query_selector("input[name=password]") else "input[type=password]"
            if not u_sel or not p_sel:
                result["note"] = "Could not find username/password fields for lockout test."
                break
            page.fill(u_sel, invalid_creds["username"])
            page.fill(p_sel, invalid_creds["password"])
            # submit
            if page.query_selector("button[type=submit]"):
                page.click("button[type=submit]")
            else:
                page.press(p_sel, "Enter")
            time.sleep(0.5)
            text = page.content().lower()
            lock_phrases = ["account locked", "temporarily locked", "too many attempts", "try again later", "locked due to", "blocked"]
            observed = [p for p in lock_phrases if p in text]
            attempt_info = {"attempt": i+1, "lock_message_present": bool(observed)}
            result["attempts"].append(attempt_info)
            if observed:
                result["observed_lockout"] = True
                result["lockout_text_sample"] = observed
                break
        except Exception as e:
            result.setdefault("errors", []).append(str(e))
            break
    return result

def test_session_logout_and_protected(page, base_url, creds, protected_path="/account"):
    result = {"logout_ok": False, "protected_after_logout": None}
    # login
    v = test_valid_login(page, base_url, creds)
    result["login_check"] = v
    if not v.get("ok"):
        result["note"] = "login did not appear successful -- cannot fully test logout/protected checks"
        return result

    # try navigate to protected page
    domain = re.sub(r"^(https?://[^/]+).*", r"\1", base_url)
    protected_url = domain + protected_path
    try:
        page.goto(protected_url, wait_until="domcontentloaded")
        time.sleep(0.5)
        # ensure access allowed
        content_after = page.content().lower()
        result["protected_accessible_pre_logout"] = True if "login" not in content_after[:500].lower() else False
    except Exception:
        result["protected_accessible_pre_logout"] = None

    # try logout via common selectors
    # attempt to click logout link/button if present
    try:
        if page.query_selector("a[href*='logout']"):
            page.click("a[href*='logout']")
        elif page.query_selector("button#logout"):
            page.click("button#logout")
        elif page.query_selector("button:has-text('Logout')"):
            page.click("button:has-text('Logout')")
        else:
            # try visiting a common logout path
            logout_candidates = ["/logout", "/account/logout", "/signout"]
            for pth in logout_candidates:
                try:
                    page.goto(domain + pth)
                    time.sleep(0.5)
                    break
                except Exception:
                    pass
    except Exception:
        pass

    # now check if protected page is blocked
    try:
        page.goto(protected_url, wait_until="domcontentloaded")
        time.sleep(0.5)
        content_after = page.content().lower()
        if "login" in content_after[:500].lower() or "sign in" in content_after[:500].lower():
            result["logout_ok"] = True
        else:
            result["logout_ok"] = False
        result["protected_after_logout"] = "login" in content_after[:500].lower()
    except Exception as e:
        result["error"] = str(e)

    return result

def test_open_redirect(page, base_url):
    # attempt to set returnUrl to external domain and see if redirect happens (open redirect detection)
    result = {"vulnerable": False, "tested_urls": []}
    try:
        # the given base_url likely already contains returnUrl param; we'll replace it
        # craft a malicious returnUrl to external site
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
        parsed = urlparse(base_url)
        # find query string and replace any returnUrl param
        q = parse_qs(parsed.query)
        evil = "https://example.com/"
        q["returnUrl"] = [evil]
        new_q = urlencode(q, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
        result["tested_urls"].append(new_url)

        page.goto(new_url, wait_until="domcontentloaded")
        time.sleep(1)
        # submit no creds (just mimic navigation to login). After login, normally app will redirect to returnUrl.
        # We cannot complete login here (sensitive), but we can check whether the login page contains the returnUrl anywhere in forms or hidden fields
        page_html = page.content()
        if evil in page_html:
            result["returnurl_reflected_in_page"] = True
        else:
            result["returnurl_reflected_in_page"] = False

        # Also check for location.replace scripts or meta refresh
        if re.search(re.escape(evil), page_html):
            result["vulnerable_reflection"] = True
        # Note: full exploit would require logging in; here we detect reflection or lack of validation.
    except Exception as e:
        result["error"] = str(e)
    return result

# --- Runner ---
def run_all_tests(creds_file="creds.json"):
    creds = load_creds(creds_file)
    base_url = creds.get("base_url")
    valid = creds.get("valid")
    invalid = creds.get("invalid")
    max_brute = creds.get("max_bruteforce_attempts", 5)
    protected_path = creds.get("protected_check_path", "/account")

    report = {
        "meta": {
            "tested_at": datetime.utcnow().isoformat() + "Z",
            "base_url": base_url
        },
        "results": {}
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            report["results"]["valid_login"] = test_valid_login(page, base_url, valid)
        except Exception as e:
            report["results"]["valid_login_error"] = str(e)

        # reload context between tests to avoid state carry-over
        context.clear_cookies()
        page = context.new_page()
        try:
            report["results"]["invalid_login"] = test_invalid_login(page, base_url, invalid)
        except Exception as e:
            report["results"]["invalid_login_error"] = str(e)

        context.clear_cookies()
        page = context.new_page()
        try:
            report["results"]["lockout_simulation"] = test_lockout_simulation(page, base_url, invalid, max_attempts=max_brute)
        except Exception as e:
            report["results"]["lockout_error"] = str(e)

        context.clear_cookies()
        page = context.new_page()
        try:
            report["results"]["session_logout_and_protected"] = test_session_logout_and_protected(page, base_url, valid, protected_path)
        except Exception as e:
            report["results"]["session_logout_error"] = str(e)

        context.clear_cookies()
        page = context.new_page()
        try:
            report["results"]["open_redirect_test"] = test_open_redirect(page, base_url)
        except Exception as e:
            report["results"]["open_redirect_error"] = str(e)

        # final housekeeping
        browser.close()

    save_report(report)
    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    run_all_tests()
