#!/usr/bin/env python3
# WALF - single-file revised version (interactive)
# Fokus: perbaikan runtime, safety (mask cookies), robust response parsing|

import os
import csv
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re
import json
import time
import uuid
import sys
import html
import base64
from difflib import SequenceMatcher
import logging
import getpass

# ----------------- CONFIG -----------------
TIMEOUT = 8
THROTTLE = 0.6
CRAWL_DEPTH = 1
ID_NUM_RANGE_DEFAULT = (1, 5)
UUID_SAMPLE_COUNT = 3
HEADERS = {"User-Agent": "WALF/1.0 (Level-3)"}
REPORT_DIR = "reports"
LOG_FILE = "walf_scan.log"

COMMON_LOGIN_PATHS = ["/login", "/signin", "/users/sign_in", "/auth/login", "/accounts/login", "/signin.php"]
ADMIN_PATHS = ["/admin", "/administrator", "/admin/dashboard", "/manage"]

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUMERIC_RE = re.compile(r"^\d+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{8,}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# PII regex (for redaction)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d")

# ----------------- logging setup -----------------
logger = logging.getLogger("walf")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

# ----------------- UTIL (scan id, finding helpers) -----------------
def gen_scan_id():
    return time.strftime("walf-%Y%m%d-%H%M%S", time.localtime())

SCAN_ID = gen_scan_id()

def gen_finding_id(seq=1):
    return f"{SCAN_ID}-F-{seq:04d}"

def assess_severity(f):
    """Heuristic scoring -> severity + numeric score"""
    score = 0.0
    resp = f.get("response", {}) or {}
    status = resp.get("status")
    sample = (resp.get("sample") or "")[:2000]

    if status == 200:
        score += 3.0
    if status and status in (401,403,404):
        score -= 2.0
    if EMAIL_RE.search(sample) or PHONE_RE.search(sample):
        score += 3.0
    if f.get("content_similarity_to_baseline") is not None:
        sim = f["content_similarity_to_baseline"]
        if sim < 0.95:
            score += 2.0
    scen = (f.get("scenario") or "").lower()
    if "idor" in scen or "hidden" in scen or "sequential" in scen or "mutation" in scen:
        score += 1.0

    if score >= 6:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"
    return severity, round(score,2)

def build_poc_curl(f, session_cookie_name="session"):
    """Build a quick PoC curl string. Replace cookie placeholder before use."""
    t = f.get("target") or f.get("action") or ""
    cookie = "SESS_FAKE"  # placeholder — user must replace with real session
    scen = (f.get("scenario") or "")
    if scen.startswith("hidden_post") or scen.startswith("hidden"):
        action = f.get("action") or t
        field = f.get("field", "id")
        value = f.get("value", "1")
        # simple form POST PoC
        return f"curl -i -X POST -b '{session_cookie_name}={cookie}' -d '{field}={value}' '{action}'"
    else:
        return f"curl -i -b '{session_cookie_name}={cookie}' '{t}'"

def dedupe_findings(findings):
    seen=set(); out=[]
    for f in findings:
        key = (f.get("scenario"), f.get("target"), str(f.get("value")), f.get("action"), f.get("field"))
        if key in seen: continue
        seen.add(key); out.append(f)
    return out

def redact_text(s):
    if not s: return s
    s = EMAIL_RE.sub("[REDACTED_EMAIL]", s)
    s = PHONE_RE.sub("[REDACTED_PHONE]", s)
    s = re.sub(r"\b\d{9,}\b", "[REDACTED_NUMBER]", s)
    return s

def ensure_reports_dir():
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
    except Exception as e:
        logger.debug(f"ensure_reports_dir error: {e}")

def export_csv(findings, fname):
    keys=["id","title","scenario","severity","score","confidence","status","owner","estimated_fix_days","poc_curl","repro_steps","target"]
    try:
        with open(fname,"w",newline="",encoding="utf-8") as fh:
            w=csv.writer(fh)
            w.writerow(keys)
            for f in findings:
                row=[
                    f.get("id",""),
                    f.get("title",""),
                    f.get("scenario",""),
                    f.get("severity",""),
                    f.get("score",""),
                    f.get("confidence",""),
                    f.get("status",""),
                    f.get("owner",""),
                    f.get("estimated_fix_days",""),
                    f.get("poc_curl",""),
                    " | ".join(f.get("repro_steps",[])),
                    f.get("target","")
                ]
                w.writerow(row)
        logger.info(f"[+] CSV exported -> {fname}")
    except Exception as e:
        logger.error(f"[-] CSV export failed: {e}")

# ----------------- HELPERS (existing) -----------------
def normalise_url(u):
    try:
        p = urlparse(u)
        return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
    except Exception:
        return u

def same_domain(a, b):
    try:
        return urlparse(a).netloc == urlparse(b).netloc
    except Exception:
        return False

def safe_get(session, url, **kwargs):
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        logger.debug(f"safe_get exception for {url}: {e}")
        return e

def safe_post(session, url, data=None, **kwargs):
    try:
        return session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        logger.debug(f"safe_post exception for {url}: {e}")
        return e

def detect_id_type(val):
    if val is None or val == "":
        return None
    v = str(val).strip()
    if UUID_RE.match(v): return "uuid"
    if NUMERIC_RE.match(v): return "numeric"
    if MD5_RE.match(v): return "md5"
    if SHA1_RE.match(v): return "sha1"
    if SHA256_RE.match(v): return "sha256"
    if BASE64_RE.match(v): return "base64-like"
    if len(v) <= 6 and v.isdigit(): return "numeric"
    if len(v) >= 20: return "long-string"
    return "unknown"

def similarity(a, b):
    try:
        return SequenceMatcher(None, a or "", b or "").ratio()
    except Exception:
        return 0.0

def response_sig(resp):
    base = {"status": None, "len": None, "sample": "", "headers": {}, "error": None}
    if isinstance(resp, Exception):
        base["error"] = str(resp)
        return base
    # safe extraction
    try:
        text = getattr(resp, "text", "") or ""
        base["status"] = getattr(resp, "status_code", None)
        base["len"] = len(text)
        base["sample"] = text[:2000]
    except Exception as e:
        base["error"] = f"read-text-error: {e}"
    try:
        base["headers"] = dict(getattr(resp, "headers", {}) or {})
    except Exception:
        base["headers"] = {}
    return base

def login_success_heuristic(resp):
    if isinstance(resp, Exception): return False
    txt = getattr(resp, "text", "") or ""
    if getattr(resp, "status_code", None) in (302,):
        return True
    low = txt.lower()
    if "logout" in low or "sign out" in low or "dashboard" in low or "my account" in low:
        return True
    if getattr(resp, "status_code", None) == 200 and ("login" not in low and "signin" not in low):
        return True
    return False

# ----------------- LOGIN DEBUG & VERIFY HELPERS -----------------
def _short(text, n=800):
    if not text: return ""
    return text[:n] + ("..." if len(text) > n else "")

def dump_login_debug(resp, session, output_logs):
    """Append structured debug about login response & session cookies into output['logs'].
    IMPORTANT: do NOT log cookie values — only cookie names.
    """
    try:
        headers = dict(getattr(resp, "headers", {}) or {}) if hasattr(resp, "headers") else {}
    except Exception:
        headers = {}
    try:
        cookie_names = list(session.cookies.get_dict().keys())
    except Exception:
        cookie_names = []
    msg = {
        "ts": time.time(),
        "level": "debug",
        "msg": (
            f"login_resp_status={getattr(resp,'status_code',None)} "
            f"history={[getattr(h,'status_code',None) for h in getattr(resp,'history',[])]} "
            f"set-cookie_keys={[k for k in headers.keys() if 'set-cookie' in k.lower() or k.lower()=='set-cookie']} "
            f"session_cookie_names={cookie_names}"
        )
    }
    output_logs.append(msg)
    try:
        body = getattr(resp, "text", "") or ""
        output_logs.append({"ts": time.time(), "level": "debug", "msg": f"login_resp_sample={_short(redact_text(body),400)}"})
    except Exception:
        pass

def verify_session_auth(session, base_url, output_logs, check_paths=None):
    """
    Check a small set of post-login endpoints to confirm we are authenticated.
    Returns (True, evidence) if pass; otherwise (False, details).
    """
    # broaden default checks; include root and common user pages
    if check_paths is None:
        check_paths = ["/", "/users", "/dashboard", "/profile", "/account", "/logout"]
    indicators = ["logout", "dashboard", "my account", "user id", "profile", "sign out", "sign-out"]
    last_sig = None
    for p in check_paths:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        last_sig = sig
        output_logs.append({"ts": time.time(), "level": "debug", "msg": f"verify GET {url} -> status={sig.get('status')} len={sig.get('len')}"} )
        body = (sig.get("sample") or "").lower()
        for ind in indicators:
            if ind in body:
                evidence = {"path": p, "indicator": ind, "status": sig.get("status")}
                output_logs.append({"ts": time.time(), "level": "info", "msg": f"verify success via {p} (indicator='{ind}')"})
                return True, evidence
    return False, {"reason": "no indicator found", "last_status": (last_sig.get("status") if last_sig else None)}

# ----------------- DETECT LOGIN -----------------
def detect_login_candidates(target, session, logs):
    base = target.rstrip("/")
    candidates = []
    for p in COMMON_LOGIN_PATHS:
        u = urljoin(base, p)
        logs.append(f"[detect] trying common path {u}")
        r = safe_get(session, u, headers=HEADERS)
        time.sleep(THROTTLE)
        if isinstance(r, Exception):
            logs.append(f"  - error {r}")
            candidates.append((u, ""))
            continue
        text = getattr(r, "text", "") or ""
        if "password" in text.lower() or "sign in" in text.lower() or "log in" in text.lower():
            candidates.append((u, text))
            logs.append(f"  - login-like page found: {u}")
        else:
            candidates.append((u, text))
    root = safe_get(session, base, headers=HEADERS)
    time.sleep(THROTTLE)
    if not isinstance(root, Exception):
        soup = BeautifulSoup(getattr(root, "text", "") or "", "html.parser")
        for f in soup.find_all("form"):
            if f.find("input", {"type":"password"}):
                action = f.get("action") or ""
                action_url = urljoin(base, action)
                candidates.append((action_url, str(f)))
                logs.append(f"[detect] form-with-password found on root -> action {action_url}")
    seen=set(); uniq=[]
    for u,html_text in candidates:
        nu = normalise_url(u)
        if nu not in seen:
            seen.add(nu); uniq.append((u,html_text))
    return uniq

def inspect_form_html(html_text):
    """
    Parse inputs and attempt to find CSRF tokens including meta tags.
    Returns: {"auth_candidates": [...], "csrf": {name: value}, "inputs": [...], "html": str(soup)}
    """
    soup = BeautifulSoup(html_text or "", "html.parser")
    inputs=[]; csrf_fields={}; auth_types=set()
    for inp in soup.find_all(("input","textarea","select")):
        name = inp.get("name")
        itype = (inp.get("type") or "text").lower()
        val = inp.get("value") or ""
        if not name:
            continue
        inputs.append({"name":name,"type":itype,"value":val})
        if "email" in name.lower() or "e-mail" in name.lower():
            auth_types.add("email")
        if "user" in name.lower() or "username" in name.lower() or "login" in name.lower():
            auth_types.add("username")
        if itype=="hidden":
            csrf_fields[name]=val

    # additional: capture meta CSRF tokens commonly used by JS
    for meta in soup.find_all("meta"):
        mname = (meta.get("name") or "").lower()
        if mname in ("csrf-token","csrf","xsrf-token","csrfmiddlewaretoken","x-csrf-token","csrf-token"):
            key = meta.get("name") or mname
            csrf_fields[key] = meta.get("content") or meta.get("value") or ""

    if not auth_types:
        for inp in soup.find_all("input"):
            ph = (inp.get("placeholder") or "").lower()
            if "email" in ph: auth_types.add("email")
            if "user" in ph or "username" in ph: auth_types.add("username")
    return {"auth_candidates": sorted(list(auth_types)) or ["unknown"], "csrf": csrf_fields, "inputs": inputs, "html": str(soup)}

# ----------------- CRAWL -----------------
def crawl_bfs(session, base_url, depth=CRAWL_DEPTH, logs=None):
    logs = logs or []
    base = base_url.rstrip("/")
    visited=set()
    queue=[(base,0)]
    found_urls=set()
    found_forms=[]
    while queue:
        url, d = queue.pop(0)
        if d>depth: continue
        nu = normalise_url(url)
        if nu in visited: continue
        visited.add(nu)
        logs.append(f"[crawl] {nu} (d={d})")
        r = safe_get(session, nu, headers=HEADERS)
        time.sleep(THROTTLE)
        if isinstance(r, Exception):
            logs.append(f"  - error {r}")
            continue
        text = getattr(r, "text", "") or ""
        soup = BeautifulSoup(text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if href.startswith("javascript:") or href.startswith("#") or href.lower().startswith("mailto:"): continue
            full = urljoin(nu, href)
            if same_domain(base, full):
                fnu = normalise_url(full)
                found_urls.add(fnu)
                if fnu not in visited:
                    queue.append((full, d+1))
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            action_url = urljoin(nu, action)
            inputs=[]
            for inp in f.find_all(("input","textarea","select")):
                name = inp.get("name")
                itype = (inp.get("type") or "text").lower()
                val = inp.get("value") or ""
                if name:
                    inputs.append({"name":name,"type":itype,"value":val})
            found_forms.append({"page":nu,"action":normalise_url(action_url),"inputs":inputs})
    return {"urls": sorted(found_urls), "forms": found_forms, "logs": logs}

# ----------------- ID DETECTION -----------------
def detect_ids_in_url(u):
    parsed = urlparse(u)
    ids=[]
    qs = parse_qs(parsed.query)
    for k,v in qs.items():
        if not v: continue
        ids.append({"location":"query","url":normalise_url(u),"param":k,"sample":v[0],"type": detect_id_type(v[0])})
    for seg in parsed.path.strip("/").split("/"):
        t = detect_id_type(seg)
        if t:
            ids.append({"location":"path","url":normalise_url(u),"param":None,"sample":seg,"type":t})
    return ids

def detect_ids_in_form(f):
    ids=[]
    for inp in f.get("inputs", []):
        name = inp.get("name")
        val = inp.get("value") or ""
        if name and ("id" in name.lower() or detect_id_type(val) in ("numeric","uuid","base64-like","md5","sha1","sha256")):
            ids.append({"location":"form","action":f.get("action"),"param":name,"sample":val,"type":detect_id_type(val)})
    return ids

def gen_numeric(start, end): return [str(i) for i in range(start, end+1)]
def gen_uuids(n): return [str(uuid.uuid4()) for _ in range(n)]
def gen_base64_samples(n=3):
    out=[]
    for i in range(n):
        out.append(base64.b64encode(f"user{i}".encode()).decode())
    return out

# ----------------- LEVEL-3 SCENARIOS -----------------
def run_sequential_path(session, template, id_values, logs):
    findings=[]
    logs.append("[1] Sequential ID Tampering (Path) - LEVEL 3")
    use_brace = "{id}" in template
    baseline = None
    for vid in id_values:
        url = template.replace("{id}", str(vid)) if use_brace else template.rstrip("/") + "/" + str(vid)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"sequential_path","target":url,"value":vid,"response":sig})
        if baseline is None and sig.get("status")==200:
            baseline = sig.get("sample","")
    numeric_vals = []
    try:
        numeric_vals = [int(v) for v in id_values if NUMERIC_RE.match(str(v))]
    except Exception:
        numeric_vals = []
    if numeric_vals:
        found200 = sum(1 for f in findings if f["response"].get("status")==200)
        if found200 >= 2:
            lo = min(numeric_vals); hi = max(numeric_vals)
            for d in range(1, 8):
                for v in (lo-d, hi+d):
                    if v <= 0: continue
                    url = template.replace("{id}", str(v)) if use_brace else template.rstrip("/") + "/" + str(v)
                    r = safe_get(session, url, headers=HEADERS)
                    sig = response_sig(r)
                    logs.append(f"  [expand] GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
                    findings.append({"scenario":"sequential_path_expand","target":url,"value":v,"response":sig})
    if baseline:
        for f in findings:
            resp = f.get("response", {}) or {}
            if resp.get("status")!=200: continue
            sim = similarity(baseline[:2000], resp.get("sample","")[:2000])
            f["content_similarity_to_baseline"] = sim
            if sim < 0.95:
                f["flag"] = "content-diff"
                logs.append(f"  [diff] {f.get('target')} similarity {sim:.2f} -> flagged")
    return findings

def run_sequential_query(session, url_template, param, id_values, logs):
    findings=[]
    logs.append("[2] Sequential ID Tampering (Query Param) - LEVEL 3")
    parsed = urlparse(url_template)
    qs = parse_qs(parsed.query)
    base_noq = parsed._replace(query=None).geturl()
    for vid in id_values:
        qs_local = dict(qs)
        qs_local[param] = [str(vid)]
        new_url = parsed._replace(query=urlencode(qs_local, doseq=True)).geturl()
        r = safe_get(session, new_url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {new_url} -> {sig.get('status')}")
        findings.append({"scenario":"sequential_query","target":new_url,"param":param,"value":vid,"response":sig})
        dup_q = f"{param}={qs_local[param][0]}&{param}={vid}"
        dup_url = base_noq + "?" + dup_q
        r2 = safe_get(session, dup_url, headers=HEADERS)
        s2 = response_sig(r2)
        logs.append(f"  GET (HPP) {dup_url} -> {s2.get('status')}")
        findings.append({"scenario":"sequential_query_hpp","target":dup_url,"param":param,"value":vid,"response":s2})
        rpost = safe_post(session, base_noq, data={param:str(vid)}, headers=HEADERS)
        sp = response_sig(rpost)
        logs.append(f"  POST {base_noq} {param}={vid} -> {sp.get('status')}")
        findings.append({"scenario":"sequential_query_post","target":base_noq,"param":param,"value":vid,"response":sp})
        mutations=[]
        try:
            if NUMERIC_RE.match(str(vid)):
                mutations.append(str(vid).zfill(4))
                mutations.append(hex(int(vid))[2:])
            mutations.append(base64.b64encode(str(vid).encode()).decode())
        except Exception:
            pass
        for m in mutations:
            qs_mut = dict(qs); qs_mut[param]=[m]
            mu = parsed._replace(query=urlencode(qs_mut,doseq=True)).geturl()
            rm = safe_get(session, mu, headers=HEADERS)
            sm = response_sig(rm)
            logs.append(f"  GET (mut) {mu} -> {sm.get('status')}")
            findings.append({"scenario":"sequential_query_mutation","target":mu,"param":param,"value":m,"response":sm})
    return findings

def try_parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None

def run_hidden_field_tests(session, form, id_candidates, logs):
    findings=[]
    logs.append("[3] Hidden Field Manipulation (POST/JSON) - LEVEL 3")
    action = form.get("action")
    post_data = {inp["name"]: inp.get("value","") for inp in form.get("inputs", [])}
    fields = [n for n in post_data.keys() if "id" in n.lower()]
    if not fields:
        fields = [n for n in post_data.keys()][:1] if post_data else []
    if not fields:
        logs.append("  - no postable id-like fields found")
        return findings
    id_pool=[]
    for it in id_candidates:
        if isinstance(it, dict):
            v = it.get("sample");
            if v: id_pool.append(str(v))
        else:
            id_pool.append(str(it))
    id_pool += [str(i) for i in range(1,6)]
    id_pool = list(dict.fromkeys(id_pool))
    for field in fields:
        for candidate in id_pool:
            data = post_data.copy(); data[field] = candidate
            # include Referer/Origin for POSTs too (increase chance accepted)
            headers_post = {**HEADERS}
            try:
                parsed_action = urlparse(action)
                headers_post["Referer"] = urljoin(action, "/")
                headers_post["Origin"] = f"{parsed_action.scheme}://{parsed_action.netloc}"
            except Exception:
                pass
            r = safe_post(session, action, data=data, headers=headers_post)
            sig = response_sig(r)
            logs.append(f"  POST {action} {field}={candidate} -> {sig.get('status')}")
            findings.append({"scenario":"hidden_post","action":action,"field":field,"value":candidate,"response":sig})
            ct = sig.get("headers", {}) or {}
            ct_val = ""
            for hk in ct:
                if hk.lower() == "content-type":
                    ct_val = ct[hk]; break
            if "application/json" in ct_val or (try_parse_json(sig.get("sample","")) is not None):
                headers_json = headers_post.copy(); headers_json["Content-Type"]="application/json"
                rj = safe_post(session, action, data=json.dumps(data), headers=headers_json)
                sj = response_sig(rj)
                logs.append(f"  POST(JSON) {action} {field}={candidate} -> {sj.get('status')}")
                findings.append({"scenario":"hidden_post_json","action":action,"field":field,"value":candidate,"response":sj})
    for field in fields:
        for candidate in id_pool[:3]:
            headers_alt = HEADERS.copy(); headers_alt["Content-Type"]="application/x-www-form-urlencoded; charset=UTF-8"
            ralt = safe_post(session, action, data={field:candidate}, headers=headers_alt)
            salt = response_sig(ralt)
            logs.append(f"  POST(alt-ct) {action} {field}={candidate} -> {salt.get('status')}")
            findings.append({"scenario":"hidden_post_altct","action":action,"field":field,"value":candidate,"response":salt})
    return findings

def run_role_response_comparison(session, url_template, compare_ids, logs):
    findings=[]
    logs.append("[4] Role Response Comparison (self-check) - LEVEL 3")
    samples=[]
    for vid in compare_ids:
        url = url_template.replace("{id}",str(vid)) if "{id}" in url_template else urljoin(url_template, str(vid))
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        txt = sig.get("sample","")
        samples.append((vid, txt, sig))
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
    if len(samples) >= 2:
        a = samples[0][1]; b = samples[1][1]
        sim = similarity(a, b)
        ja = try_parse_json(a); jb = try_parse_json(b)
        json_diff = None
        if ja is not None and jb is not None and isinstance(ja, dict) and isinstance(jb, dict):
            na = normalize_json(ja); nb = normalize_json(jb)
            keys_a = set(na.keys()); keys_b = set(nb.keys())
            added = list(keys_b - keys_a); removed = list(keys_a - keys_b)
            json_diff = {"added_keys": added, "removed_keys": removed}
            logs.append(f"  JSON diff -> added:{added} removed:{removed}")
        combined = a + "\n" + b
        emails = list(set(EMAIL_RE.findall(combined)))
        phones = list(set(PHONE_RE.findall(combined)))
        findings.append({"scenario":"role_response_comparison","pairs":[(samples[0][0],samples[1][0])],"similarity":sim,"json_diff":json_diff,"emails":emails,"phones":phones,"response":{}})
        logs.append(f"  similarity={sim:.2f} ; emails_found={len(emails)} phones_found={len(phones)}")
    return findings

COMMON_ADMIN_PATHS = ADMIN_PATHS + ["/admin/login","/admin-console","/manage/account","/cms","/dashboard/admin","/admin/api","/api/admin"]
COMMON_GUESS_SUFFIXES = ["/orders/{}","/order/{}","/invoices/{}","/transactions/{}"]

def run_vertical_privilege(session, base_url, logs):
    findings=[]
    logs.append("[5] Vertical Privilege Escalation (/admin) - LEVEL 3")
    for p in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {p} -> {sig.get('status')}")
        findings.append({"scenario":"vertical_admin","target":url,"response":sig})
        probe_headers = [
            {"X-Original-URL": p},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": urlparse(base_url).netloc},
        ]
        for hh in probe_headers:
            rh = safe_get(session, url, headers={**HEADERS, **hh})
            sh = response_sig(rh)
            logs.append(f"    header-probe {list(hh.keys())[0]} -> {sh.get('status')}")
            findings.append({"scenario":"vertical_admin_header_probe","target":url,"headers":hh,"response":sh})
    return findings

def run_horizontal_privilege(session, base_url, profile_template, id_values, logs):
    findings=[]
    logs.append("[6] Horizontal Privilege Escalation - LEVEL 3")
    for vid in id_values:
        url = profile_template.replace("{id}",str(vid)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{vid}")
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"horizontal_profile","target":url,"value":vid,"response":sig})
        for sfx in COMMON_GUESS_SUFFIXES:
            guess = urljoin(base_url, sfx.format(vid))
            rg = safe_get(session, guess, headers=HEADERS)
            sg = response_sig(rg)
            logs.append(f"    GET {guess} -> {sg.get('status')}")
            findings.append({"scenario":"horizontal_nested_guess","target":guess,"value":vid,"response":sg})
    if len(id_values) >= 2:
        a = id_values[0]; b = id_values[1]
        u_a = profile_template.replace("{id}",str(a)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{a}")
        u_b = profile_template.replace("{id}",str(b)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{b}")
        ra = safe_get(session, u_a, headers=HEADERS); rb = safe_get(session, u_b, headers=HEADERS)
        ta, tb = getattr(ra,"text","") or "", getattr(rb,"text","") or ""
        sim = similarity(ta, tb)
        logs.append(f"  profile pair similarity {a}/{b} -> {sim:.2f}")
        findings.append({"scenario":"horizontal_semantic_compare","pair":(a,b),"similarity":sim,"response":{}})
    return findings

def normalize_json(obj):
    if isinstance(obj, dict):
        out={}
        for k,v in obj.items():
            if any(x in k.lower() for x in ["created_at","updated_at","timestamp","ts","expires_at","expiry","last_login","id_token","csrf_token"]):
                continue
            out[k]=normalize_json(v)
        return out
    if isinstance(obj, list):
        return [normalize_json(x) for x in obj]
    return obj

def run_level3_advanced_tests(session, base_url, id_info, logs):
    findings=[]
    logs.append("[L3] Starting Level-3 advanced orchestration")
    numeric_ids = []
    profile_template = None
    for it in id_info:
        if it.get("type")=="numeric":
            try: numeric_ids.append(int(it.get("sample")))
            except: pass
        if it.get("location")=="path" and "/profile/" in (it.get("url") or "") and profile_template is None:
            p = urlparse(it.get("url"))
            segs = p.path.strip("/").split("/")
            new=[]; found=False
            for s in segs:
                if NUMERIC_RE.match(s) and not found:
                    new.append("{id}"); found=True
                else:
                    new.append(s)
            if found:
                profile_template = urljoin(base_url, "/".join(new))
    if not profile_template:
        profile_template = urljoin(base_url, "/profile/{id}")
    id_pool = [str(i) for i in (numeric_ids if numeric_ids else [1,2,3,4,5])]
    id_pool += [str(uuid.uuid4()) for _ in range(3)]
    id_pool = list(dict.fromkeys(id_pool))
    findings += run_sequential_path(session, profile_template, id_pool, logs)
    q_candidate=None; qparam=None
    for s in id_info:
        u = s.get("url") or ""
        parsed = urlparse(u); qs = parse_qs(parsed.query)
        if qs:
            for k,v in qs.items():
                if v and detect_id_type(v[0]) in ("numeric","uuid","unknown"):
                    q_candidate = u; qparam = k; break
        if q_candidate: break
    if q_candidate:
        findings += run_sequential_query(session, q_candidate, qparam, id_pool, logs)
    for it in id_info:
        if it.get("location")=="form":
            try:
                findings.extend(run_hidden_field_tests(session, {"action":it.get("action"), "inputs":[{"name":it.get("param"), "type":"text", "value":it.get("sample")}]}, [it], logs))
            except Exception as e:
                logs.append(f"  [l3] hidden test error: {e}")
    for s in id_info:
        if s.get("type")=="base64-like":
            sample = s.get("sample")
            try:
                dec = base64.b64decode(sample).decode(errors="ignore")
                logs.append(f"  [l3] base64 decode {sample} -> {dec}")
                if dec.isdigit():
                    pool = [dec] + [str(int(dec)+i) for i in (-1,1,2)]
                    findings += run_sequential_path(session, profile_template, pool, logs)
            except Exception as e:
                logs.append(f"  [l3] base64 decode err: {e}")
    for s in id_info:
        if s.get("type")=="uuid":
            try:
                muts = [str(uuid.uuid4()) for _ in range(4)]
                findings += run_sequential_path(session, profile_template, muts, logs)
            except Exception:
                pass
            break
    if len(id_pool) >= 2:
        a = id_pool[0]; b = id_pool[1]
        ua = profile_template.replace("{id}",str(a)); ub = profile_template.replace("{id}",str(b))
        t0 = time.time(); ra = safe_get(session, ua, headers=HEADERS); ta = time.time()-t0
        t1 = time.time(); rb = safe_get(session, ub, headers=HEADERS); tb = time.time()-t1
        logs.append(f"  [timing] {ua} -> {ta:.3f}s ; {ub} -> {tb:.3f}s")
        findings.append({"scenario":"timing_probe","targets":[ua,ub],"times":[ta,tb],"response":{}})
        if abs(ta-tb) > 0.5:
            findings.append({"scenario":"timing_anomaly","details":f"time_diff={abs(ta-tb):.3f}s","response":{}})
    logs.append("[L3] Completed Level-3 orchestration")
    return findings

# ----------------- RENDER HTML (improved summary) -----------------
def render_html_report(final_data, filename):
    def badge_for(t):
        cls = "badge-unknown"
        txt = t or ""
        if t=="numeric": cls="badge-numeric"
        elif t=="uuid": cls="badge-uuid"
        elif t=="base64-like": cls="badge-base64"
        elif t in ("md5","sha1","sha256"): cls="badge-hash"
        elif t=="long-string": cls="badge-long"
        return f'<span class="badge {cls}">{html.escape(txt)}</span>'

    findings = final_data.get("findings", []) or []
    counts = {"High":0,"Medium":0,"Low":0,"Unknown":0}
    for f in findings:
        sev = f.get("severity") or "Unknown"
        if sev not in counts: counts["Unknown"] += 1
        else: counts[sev] += 1

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    scan_id = final_data.get("scan_id", "")
    total_endpoints = final_data.get("found_urls_count", 0)

    html_parts = []
    html_parts.append(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WALF Report - {html.escape(final_data.get('url',''))}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{font-family:Inter,Segoe UI,Helvetica,Arial,sans-serif;background:#f4f6f8;color:#222;margin:0;padding:24px}}
  .card{{background:#fff;border-radius:10px;padding:18px;margin-bottom:18px;box-shadow:0 6px 18px rgba(24,39,75,0.06)}}
  h1{{margin:0 0 6px 0;font-size:20px;color:#0b2f5a}}
  .muted{{color:#6b7280;font-size:13px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  th,td{{padding:8px;border-bottom:1px solid #eef2f7;text-align:left;font-size:13px}}
  th{{background:#fafafa;color:#374151}}
  .badge{{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;color:#fff}}
  .badge-numeric{{background:#0366d6}}
  .badge-uuid{{background:#6f42c1}}
  .badge-base64{{background:#d97706}}
  .badge-hash{{background:#059669}}
  .badge-long{{background:#7c3aed}}
  .badge-unknown{{background:#6b7280}}
  .mono{{font-family:Menlo,monospace;font-size:13px;background:#0b1220;color:#dbeafe;padding:8px;border-radius:6px;white-space:pre-wrap;overflow:auto}}
  details{{margin-top:8px}}
  .scenario-title{{font-weight:600;margin:0 0 6px 0;font-size:15px;color:#0b3b61}}
  .small{{font-size:13px;color:#475569}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:12px;}}
  .stat{{padding:8px;border-radius:8px;background:#f8fafc;text-align:center}}
  .stat .num{{font-weight:700;font-size:18px;color:#0b3b61}}
</style>
</head><body>
<div class="card"><h1>WALF — IDOR & Access Tests</h1>
<div class="muted">Target: {html.escape(final_data.get('url','-'))} &nbsp; • &nbsp; Generated: {now} &nbsp; • &nbsp; Scan ID: {html.escape(scan_id)}</div>
</div>""")

    # summary cards
    html_parts.append('<div class="card"><h2 class="scenario-title">Summary</h2>')
    html_parts.append('<div class="summary-grid">')
    html_parts.append(f'<div class="stat"><div class="small">Total Endpoints</div><div class="num">{total_endpoints}</div></div>')
    html_parts.append(f'<div class="stat"><div class="small">Findings (High)</div><div class="num">{counts["High"]}</div></div>')
    html_parts.append(f'<div class="stat"><div class="small">Findings (Medium)</div><div class="num">{counts["Medium"]}</div></div>')
    html_parts.append(f'<div class="stat"><div class="small">Findings (Low)</div><div class="num">{counts["Low"]}</div></div>')
    html_parts.append('</div></div>')

    # top metadata
    html_parts.append('<div class="card"><div class="grid">')
    html_parts.append(f'<div><strong>Login path(s)</strong><div class="small">')
    if final_data.get("login_detected_paths"):
        for p in final_data["login_detected_paths"]:
            html_parts.append(f'<div>{html.escape(p)}</div>')
    else:
        html_parts.append('<div class="muted">No login path detected</div>')
    html_parts.append('</div></div>')
    html_parts.append(f'<div><strong>Auth candidates</strong><div class="small">{" , ".join(final_data.get("auth_type_candidates",[])) or "-"}</div></div>')
    html_parts.append(f'<div><strong>Login used</strong><div class="small">{html.escape(final_data.get("login_path_used") or "-")}</div></div>')
    html_parts.append(f'<div><strong>Login success</strong><div class="small">{"Yes" if final_data.get("login_success") else "No"}</div></div>')
    html_parts.append('</div></div>')

    # identifiers table
    html_parts.append('<div class="card"><h2 class="scenario-title">Found Identifiers</h2>')
    ids = final_data.get("found_ids", [])
    if ids:
        html_parts.append('<table><thead><tr><th>Location</th><th>URL / Action</th><th>Param</th><th>Sample</th><th>Type</th></tr></thead><tbody>')
        for it in ids:
            loc = html.escape(it.get("location",""))
            url_or_action = html.escape(it.get("url") or it.get("action") or "")
            param = html.escape(str(it.get("param") or "-"))
            sample = html.escape(str(it.get("sample") or ""))
            typ = it.get("type") or "unknown"
            badge = badge_for(typ)
            html_parts.append(f'<tr><td>{loc}</td><td style="max-width:420px;word-break:break-all">{url_or_action}</td><td>{param}</td><td>{sample}</td><td>{badge}</td></tr>')
        html_parts.append('</tbody></table>')
    else:
        html_parts.append('<div class="muted">No identifiers detected.</div>')
    html_parts.append('</div>')

    # findings index table (compact)
    html_parts.append('<div class="card"><h2 class="scenario-title">Findings Index</h2>')
    if findings:
        html_parts.append('<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Owner</th><th>PoC</th></tr></thead><tbody>')
        for f in findings:
            fid = html.escape(f.get("id","-"))
            title = html.escape(f.get("title", f.get("scenario","")))
            sev = html.escape(str(f.get("severity","-")))
            conf = html.escape(str(f.get("confidence","-")))
            owner = html.escape(str(f.get("owner","-") or "-"))
            poc = html.escape(f.get("poc_curl",""))
            poc_short = poc[:80] + ("..." if len(poc)>80 else "")
            html_parts.append(f'<tr><td>{fid}</td><td style="max-width:320px;word-break:break-all">{title}</td><td>{sev}</td><td>{conf}</td><td>{owner}</td><td><details><summary class="small">{poc_short}</summary><div class="mono">{poc}</div></details></td></tr>')
        html_parts.append('</tbody></table>')
    else:
        html_parts.append('<div class="muted">No findings recorded.</div>')
    html_parts.append('</div>')

    # detailed findings
    html_parts.append('<div class="card"><h2 class="scenario-title">Findings — Details</h2>')
    if findings:
        for f in findings:
            header = html.escape(f.get("title", f.get("scenario","")))
            html_parts.append(f'<div style="margin-bottom:12px;"><strong>{header}</strong>')
            meta_line = f"ID: {html.escape(f.get('id','-'))} • Severity: {html.escape(str(f.get('severity','-')))} • Confidence: {html.escape(str(f.get('confidence','-')))}"
            html_parts.append(f'<div class="small">{meta_line}</div>')
            html_parts.append('<div class="small" style="margin-top:6px;"><strong>PoC / Repro (replace session cookie placeholder with a real session):</strong></div>')
            html_parts.append(f'<div class="mono">{html.escape(f.get("poc_curl",""))}</div>')
            det = f.get("response",{}) or {}
            det_sample = f.get("detection_sample")
            if det_sample:
                html_parts.append('<div class="small" style="margin-top:6px;"><strong>Detection response (authenticated)</strong></div>')
                html_parts.append(f'<details><summary class="small">View detection sample</summary><div class="mono">{html.escape(det_sample[:4000])}</div></details>')
            sample = html.escape(det.get("sample_redacted", det.get("sample","")[:1000]))
            html_parts.append('<details><summary class="small">View redacted response sample (from recorded response)</summary>')
            html_parts.append(f'<div class="mono">{sample}</div></details>')
            if f.get("notes"):
                html_parts.append(f'<div class="small" style="margin-top:6px;"><strong>Notes:</strong> {html.escape(f.get("notes"))}</div>')
            html_parts.append('</div>')
    else:
        html_parts.append('<div class="muted">No detailed findings.</div>')
    html_parts.append('</div>')

    # recommendations
    html_parts.append('<div class="card"><h2 class="scenario-title">Recommendations</h2>')
    recs = final_data.get("recommendations", [])
    if recs:
        html_parts.append('<ul>')
        for r in recs:
            html_parts.append(f'<li>{html.escape(r)}</li>')
        html_parts.append('</ul>')
    else:
        html_parts.append('<div class="muted">No recommendations.</div>')
    html_parts.append('</div>')

    # execution logs
    html_parts.append('<div class="card"><h2 class="scenario-title">Execution Logs</h2>')
    logs = final_data.get("logs", [])
    if logs:
        lines=[]
        for l in logs:
            if isinstance(l, dict):
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(l.get("ts", time.time())))
                lines.append(f"[{l.get('level','info').upper()}] {ts} - {html.escape(l.get('msg',''))}")
            else:
                lines.append(html.escape(str(l)))
        safe_logs = "\n".join(lines)
        html_parts.append(f'<div class="mono">{safe_logs}</div>')
    else:
        html_parts.append('<div class="muted">No logs captured.</div>')
    html_parts.append('</div>')

    meta = final_data.get("meta", {})
    html_parts.append(f'<div class="card"><div class="small">Tool meta: timeout={meta.get("timeout")}s • throttle={meta.get("throttle")}s • crawl_depth={meta.get("crawl_depth")} • report_id={html.escape(scan_id)}</div></div>')

    html_parts.append("</body></html>")

    html_content = "\n".join(html_parts)
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        logger.info(f"Laporan HTML berhasil disimpan -> {filename}")
    except Exception as e:
        logger.error(f"Gagal menyimpan laporan HTML: {e}")

# ----------------- FINALIZATION / ENRICHMENT -----------------
def finalize_and_export(output, report_base_name):
    """Dedupe, enrich findings, redact samples, save JSON/CSV/HTML"""
    ensure_reports_dir()
    raw_findings = output.get("findings", []) or []
    deduped = dedupe_findings(raw_findings)
    enriched=[]
    seq=1
    for f in deduped:
        ff = dict(f)  # copy
        ff.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        ff.setdefault("id", gen_finding_id(seq)); seq+=1
        sev, score = assess_severity(ff)
        ff["severity"] = ff.get("severity", sev)
        ff["score"] = ff.get("score", score)
        ff["confidence"] = ff.get("confidence", "High" if ff["score"] > 4 else "Medium")
        ff["status"] = ff.get("status", "Open")
        ff["owner"] = ff.get("owner", None)
        ff["estimated_fix_days"] = ff.get("estimated_fix_days", 1)
        ff["poc_curl"] = ff.get("poc_curl") or build_poc_curl(ff)
        ff["repro_steps"] = ff.get("repro_steps", ["See PoC curl above (replace session cookie)"])
        if "response" in ff:
            ff["response"]["sample_redacted"] = redact_text(ff["response"].get("sample",""))
            ff["detection_sample"] = ff["response"].get("sample","")
        if not ff.get("title"):
            ff["title"] = str(ff.get("scenario") or "Finding")
        enriched.append(ff)

    raw_logs = output.get("logs", []) or []
    structured_logs=[]
    for item in raw_logs:
        if isinstance(item, dict) and set(("ts","level","msg")).issubset(set(item.keys())):
            structured_logs.append(item)
        else:
            structured_logs.append({"ts": time.time(), "level": "info", "msg": str(item)})

    final = {
        "scan_id": SCAN_ID,
        "url": output.get("url"),
        "login_detected_paths": output.get("login_detected_paths"),
        "auth_type_candidates": output.get("auth_type_candidates"),
        "login_path_used": output.get("login_path_used"),
        "auth_type_used": output.get("auth_type_used"),
        "login_success": output.get("login_success"),
        "found_urls_count": len(output.get("found_urls", [])),
        "found_forms_count": len(output.get("found_forms", [])),
        "found_ids": output.get("found_ids"),
        "findings": enriched,
        "errors": output.get("errors"),
        "recommendations": output.get("recommendations"),
        "logs": structured_logs,
        "meta": output.get("meta", {})
    }

    safe_base = f"{SCAN_ID}_{report_base_name}"
    html_file = os.path.join(REPORT_DIR, f"{safe_base}.html")
    json_file = os.path.join(REPORT_DIR, f"{safe_base}.json")
    csv_file = os.path.join(REPORT_DIR, f"{safe_base}.csv")

    try:
        with open(json_file, "w", encoding="utf-8") as fh:
            json.dump(final, fh, indent=2, ensure_ascii=False)
        logger.info(f"[+] Hasil JSON berhasil disimpan -> {json_file}")
    except Exception as e:
        logger.error(f"[-] Gagal menyimpan JSON: {e}")

    try:
        export_csv(final["findings"], csv_file)
    except Exception as e:
        logger.error(f"[-] Gagal menyimpan CSV: {e}")

    try:
        render_html_report(final, html_file)
    except Exception as e:
        logger.error(f"[-] Gagal render HTML: {e}")

    return final, html_file, json_file, csv_file

# ----------------- CLI BANNER -----------------
def print_banner():
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║              WALF - Web Access Logic Framework           ║")
    print("║   Advanced IDOR & Privilege Escalation Testing Tool      ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    print(f"[+] Scan ID: {SCAN_ID}")
    print("[+] Mode: Full Flow (Login → Crawl → Access Logic Scenarios)")
    print("[+] Description: Automated framework to detect IDOR & PrivEsc")
    print("----------------------------------------------------------------\n")

# ----------------- MAIN FLOW -----------------
def validate_target_url(url):
    """Validate and sanitize target URL"""
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith(('http://', 'https://')):
        raise ValueError("URL must start with http:// or https://")
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL format")
    # For dev convenience allow localhost without explicit port
    return url

def main():
    try:
        print_banner()
        target = input("⚡ Target URL (contoh: http://127.0.0.1:5002): ").strip()
        try:
            target = validate_target_url(target)
        except Exception as ve:
            print(f"Input URL tidak valid: {ve}")
            return

        report_base_name = input("Masukkan nama dasar untuk file laporan (contoh: report_website): ").strip()
        if not report_base_name:
            try:
                domain_name = urlparse(target).netloc.replace('.', '_').replace(':', '_')
                report_base_name = f"{domain_name}"
            except:
                report_base_name = "idor_report"
            print(f"Nama dasar tidak diisi, menggunakan default: '{report_base_name}'")

        ensure_reports_dir()

        session = requests.Session(); session.headers.update(HEADERS)
        output = {"url": target, "login_detected_paths": [], "auth_type_candidates": [], "login_path_used": None, "auth_type_used": None, "login_success": False, "found_urls": [], "found_forms": [], "found_ids": [], "findings": [], "errors": [], "recommendations": [], "logs": [], "meta": {"timeout": TIMEOUT, "throttle": THROTTLE, "crawl_depth": CRAWL_DEPTH}}

        # 1) Detect login
        try:
            candidates = detect_login_candidates(target, session, output["logs"])
            output["login_detected_paths"] = [c[0] for c in candidates]
            for url, html_src in candidates:
                info = inspect_form_html(html_src)
                for a in info["auth_candidates"]:
                    if a not in output["auth_type_candidates"]:
                        output["auth_type_candidates"].append(a)
                output["logs"].append({"ts": time.time(), "level": "debug", "msg": f"[detect] inspected {url} -> auth candidates {info['auth_candidates']}; csrf_keys={list(info['csrf'].keys())}"})
        except Exception as e:
            output["errors"].append(f"Error detecting login: {e}")
            output["logs"].append({"ts": time.time(), "level": "error", "msg": str(e)})

        # 2) choose auth mode
        chosen_mode=None
        if output["auth_type_candidates"]:
            print("\nDetected authentication candidate types:", output["auth_type_candidates"])
            if "email" in output["auth_type_candidates"] and "username" in output["auth_type_candidates"]:
                print("Pilih mode login: 1. Email  2. Username  3. Coba keduanya")
                ch = input("Masukkan pilihan (1/2/3): ").strip()
                if ch=="1": chosen_mode="email"
                elif ch=="2": chosen_mode="username"
                else: chosen_mode="both"
            elif "email" in output["auth_type_candidates"]:
                chosen_mode="email"; print("Pilih mode login otomatis: email")
            elif "username" in output["auth_type_candidates"]:
                chosen_mode="username"; print("Pilih mode login otomatis: username")
            else:
                chosen_mode="both"
        else:
            print("\nTidak terdeteksi auth type otomatis. Kamu bisa mencoba login manual atau lanjut tanpa login.")
            choice = input("Coba login manual? (y/n): ").strip().lower()
            if choice=="y":
                chosen_mode = input("Pilih mode manual (email/username): ").strip().lower()
            else:
                chosen_mode = None

        # 3) ask credentials (improved verification logic)
        cred_provided=False; cred_mode_used=None
        if chosen_mode in ("email","username","both"):
            modes = [chosen_mode] if chosen_mode in ("email","username") else ["email","username"]
            for m in modes:
                ans = input(f"\nMasukkan credential untuk metode '{m}'? (y/n): ").strip().lower()
                if ans != "y":
                    output["logs"].append({"ts": time.time(), "level":"info", "msg": f"user skipped credentials for {m}"})
                    continue
                if m=="email":
                    user = input("  Email: ").strip()
                else:
                    user = input("  Username: ").strip()
                pwd = getpass.getpass("  Password (input hidden): ").strip()
                login_url = output["login_detected_paths"][0] if output["login_detected_paths"] else urljoin(target, "/login")
                output["logs"].append({"ts": time.time(), "level":"info", "msg": f"[login] attempting {m} -> {login_url} (credentials not saved to disk)"})

                # GET login page first (to obtain CSRF, session cookies)
                page = safe_get(session, login_url, headers=HEADERS)
                time.sleep(THROTTLE)
                form_info = {}
                if not isinstance(page, Exception):
                    form_info = inspect_form_html(getattr(page,"text","") or "")

                # build payload from detected csrf and inputs
                payload = {}
                for k,v in form_info.get("csrf",{}).items(): payload[k]=v

                if m=="email":
                    uname_field = None
                    for inp in form_info.get("inputs",[]):
                        if "email" in inp["name"].lower(): uname_field=inp["name"]; break
                    if not uname_field: uname_field="email"
                    payload[uname_field]=user
                else:
                    uname_field=None
                    for inp in form_info.get("inputs",[]):
                        if "user" in inp["name"].lower() or "username" in inp["name"].lower(): uname_field=inp["name"]; break
                    if not uname_field: uname_field="username"
                    payload[uname_field]=user

                pwd_field=None
                for inp in form_info.get("inputs",[]):
                    if inp["type"]=="password":
                        pwd_field=inp["name"]; break
                if not pwd_field: pwd_field="password"
                payload[pwd_field]=pwd

                action_post = login_url
                try:
                    soup = BeautifulSoup(getattr(page,"text","") or "", "html.parser")
                    for fobj in soup.find_all("form"):
                        if fobj.find("input", {"type":"password"}):
                            action = fobj.get("action") or ""
                            action_post = urljoin(login_url, action)
                            break
                except Exception:
                    pass

                # capture cookies before POST (we will log only names)
                cookies_before = session.cookies.get_dict().copy()

                headers_post = {**session.headers}
                try:
                    headers_post.update({
                        "Referer": login_url,
                        "Origin": f"{urlparse(login_url).scheme}://{urlparse(login_url).netloc}"
                    })
                except Exception:
                    pass

                resp = safe_post(session, action_post, data=payload, headers=headers_post)
                sig = response_sig(resp)
                dump_login_debug(resp, session, output["logs"])

                cookies_after = session.cookies.get_dict().copy()
                new_cookie_keys = set(cookies_after.keys()) - set(cookies_before.keys())

                heuristic_ok = login_success_heuristic(resp)

                verified = False
                evidence = {}

                if new_cookie_keys:
                    verified = True
                    evidence = {"reason":"cookies_set", "new_cookies": list(new_cookie_keys)}
                else:
                    if heuristic_ok and getattr(resp, "history", None):
                        verified = True
                        evidence = {"reason":"redirect_in_history", "history":[getattr(r,'status_code',None) for r in getattr(resp,'history',[])]}
                    else:
                        verified, evidence = verify_session_auth(session, target, output["logs"])
                        if not verified and heuristic_ok:
                            verified = True
                            evidence = {"reason":"heuristic_only_no_indicator", "note":"accepted as likely success - review logs"}

                if (not verified) and heuristic_ok:
                    try:
                        headers_json = {**headers_post, "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
                        resp2 = safe_post(session, action_post, data=json.dumps(payload), headers=headers_json)
                        dump_login_debug(resp2, session, output["logs"])
                        verified2, evidence2 = verify_session_auth(session, target, output["logs"])
                        if verified2:
                            verified = True
                            evidence = evidence2
                            resp = resp2
                            sig = response_sig(resp2)
                    except Exception:
                        pass

                output["findings"].append({"action":"login_attempt","method":m,"url":action_post,"success":bool(verified),"response":sig})
                output["logs"].append({"ts": time.time(), "level":"info", "msg": f"[login] POST {action_post} -> status {sig.get('status')} ; heuristic_ok={heuristic_ok} ; verified={verified} ; evidence={evidence}"})

                if verified:
                    print(f"[+] Login berhasil sebagai {user} (verified)")
                    output["login_success"]=True
                    output["login_path_used"]=action_post
                    output["auth_type_used"]=m
                    cred_provided=True; cred_mode_used=m
                    break
                else:
                    print(f"[-] Login gagal / tidak terverifikasi untuk mode {m} (cek logs).")
                    output["logs"].append({"ts": time.time(), "level":"warning", "msg": f"login attempt failed / not verified for {m}"})
        else:
            output["logs"].append({"ts": time.time(), "level":"info", "msg": "No credentials provided / chosen. Proceeding as guest."})

        # 4) Crawl
        print("\n[+] Crawling halaman untuk menemukan link/form...")
        crawl_res = crawl_bfs(session, target, depth=CRAWL_DEPTH, logs=output["logs"])
        urls = crawl_res["urls"]; forms = crawl_res["forms"]
        output["found_urls"]=urls; output["found_forms"]=forms
        for u in urls:
            print("    ", u)
        print("    (forms:", len(forms), "found)")
        time.sleep(0.5)

        # 5) Detect ids
        id_candidates=[]
        for u in urls: id_candidates.extend(detect_ids_in_url(u))
        for f in forms: id_candidates.extend(detect_ids_in_form(f))
        uniq=[]; seen=set()
        for it in id_candidates:
            key=(it.get("location"), it.get("url") or it.get("action"), it.get("param"), it.get("sample"))
            if key not in seen:
                seen.add(key); uniq.append(it)
        output["found_ids"]=uniq

        if uniq:
            print("\n[+] Terdeteksi identifier:")
            for it in uniq:
                loc = it.get("location")
                url_or_action = it.get("url") or it.get("action") or "-"
                param = it.get("param")
                sample = it.get("sample")
                typ = it.get("type")
                print("    ", f"{loc} {url_or_action} -> {param} = {sample} ({typ})")
        else:
            print("\n[+] Tidak menemukan identifier otomatis. Kamu bisa input manual ID range untuk testing.")
        numeric_start, numeric_end = ID_NUM_RANGE_DEFAULT
        if any(i.get("type")=="numeric" for i in uniq):
            ans = input("\nGunakan auto-generate numeric ID range default 1-5? (y/n): ").strip().lower()
            if ans=="n":
                try:
                    s = int(input("  mulai (angka): ").strip()); e = int(input("  akhir (angka): ").strip())
                    numeric_start, numeric_end = s,e
                except Exception:
                    print("  input invalid, pakai default 1-5")
        else:
            ans = input("\nTidak ada numeric ID terdeteksi. Mau pakai numeric 1-5 untuk uji? (y/n): ").strip().lower()
            if ans=="y": numeric_start, numeric_end = ID_NUM_RANGE_DEFAULT
        numeric_ids = [str(i) for i in range(numeric_start, numeric_end+1)]
        uuid_samples = [str(uuid.uuid4()) for _ in range(UUID_SAMPLE_COUNT)]
        id_test_pool = numeric_ids + uuid_samples

        # 6) Run scenarios (level3)
        print("\n[+] Mulai IDOR testing...")
        profile_template = None
        for u in urls:
            segs = urlparse(u).path.strip("/").split("/")
            new=[]; found_num=False
            for s in segs:
                if NUMERIC_RE.match(s):
                    new.append("{id}"); found_num=True
                else:
                    new.append(s)
            if found_num:
                profile_template = urljoin(target, "/".join(new)); break
        if not profile_template:
            profile_template = urljoin(target, "/profile/{id}")

        scen1 = run_sequential_path(session, profile_template, numeric_ids, output["logs"])
        output["findings"].extend(scen1)

        query_candidate=None; qparam=None
        for u in urls:
            parsed=urlparse(u); qs=parse_qs(parsed.query)
            for k,v in qs.items():
                if v and (detect_id_type(v[0]) in ("numeric","uuid","unknown")):
                    query_candidate=u; qparam=k; break
            if query_candidate: break
        scen2=[]
        if query_candidate:
            scen2 = run_sequential_query(session, query_candidate, qparam, numeric_ids, output["logs"])
            output["findings"].extend(scen2)
        else:
            output["logs"].append({"ts": time.time(), "level":"debug", "msg": "No query param candidate for sequential query tests."})

        scen3=[]
        for f in forms:
            scen3.extend(run_hidden_field_tests(session, f, id_test_pool, output["logs"]))
        output["findings"].extend(scen3)

        compare_ids = numeric_ids[:2] if len(numeric_ids)>=2 else numeric_ids
        scen4 = run_role_response_comparison(session, profile_template, compare_ids, output["logs"])
        output["findings"].extend(scen4)

        scen5 = run_vertical_privilege(session, target, output["logs"])
        output["findings"].extend(scen5)

        scen6 = run_horizontal_privilege(session, target, profile_template, numeric_ids, output["logs"])
        output["findings"].extend(scen6)

        # orchestrator
        try:
            scen_l3 = run_level3_advanced_tests(session, target, output["found_ids"], output["logs"])
            output["findings"].extend(scen_l3)
        except Exception as e:
            output["logs"].append({"ts": time.time(), "level":"error", "msg": f"[l3] orchestrator error: {e}"})

        # ensure response fields exist
        for f in output["findings"]:
            if 'response' not in f or f.get("response") is None:
                f['response'] = {"status": None, "len": None, "sample": "", "headers": {}, "error": None}

        # Summaries printing (kept concise)
        print()
        print("[+] Summary of key scenario outputs (console):")
        print(f"  - Sequential Path tests: {len(scen1)} requests")
        print(f"  - Sequential Query tests: {len(scen2)} requests")
        print(f"  - Hidden-field tests: {len(scen3)} requests")
        print(f"  - Role comparison tests: {len(scen4)}")
        print(f"  - Vertical/admin probes: {len(scen5)}")
        print(f"  - Horizontal probes: {len(scen6)}")

        # recommendations & finalize (minimal)
        output["recommendations"].append("Review findings manually; heuristics can produce false positives.")
        if output["found_ids"]:
            output["recommendations"].append("Lakukan targeted IDOR tests pada identifier yang terdeteksi.")
        else:
            output["recommendations"].append("Jika tidak ada identifier, coba tingkatkan crawl depth atau gunakan Playwright untuk discover API/XHR.")

        # finalize, enrich, export
        final, html_file, json_file, csv_file = finalize_and_export(output, report_base_name)

        print("\n✔ Testing complete!")
        print(f"📄 Reports saved:\n  - HTML: {html_file}\n  - JSON: {json_file}\n  - CSV:  {csv_file}")
        print("\nSelesai. Ingat: jangan menyimpan kredensial di file; tool ini tidak menyimpan kredensial ke output.")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    except Exception as e:
        logger.exception(f"Fatal error in main: {e}")
        print(f"[-] Fatal error: {e}")

if __name__ == "__main__":
    main()
