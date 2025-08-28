#!/usr/bin/env python3
"""
idor_full_flow_html.py
Interactive single-file tool:
- Auto-detect login path & auth type (email/username)
- Ask credentials (if detected) and validate login
- On success: Crawl & list URLs/forms
- Detect ID types (numeric, uuid, base64-like, hash)
- Run 6 IDOR scenarios (see below)
- Produce an HTML report (styled, collapsible, colored badges)
- Does NOT save credentials to disk or embed them in output
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re, json, time, uuid, sys, html
from difflib import SequenceMatcher

# ----------------- CONFIG -----------------
TIMEOUT = 8
THROTTLE = 0.6      # delay between requests
CRAWL_DEPTH = 1     # keep small by default (adjust if needed)
ID_NUM_RANGE_DEFAULT = (1, 5)
UUID_SAMPLE_COUNT = 3
HEADERS = {"User-Agent": "IDOR-Tool/1.0 (prototype)"}
# --- PERUBAHAN 1: Menghapus REPORT_FILENAME dari sini agar dinamis ---
# REPORT_FILENAME = "idor_report.html" 

COMMON_LOGIN_PATHS = ["/login", "/signin", "/users/sign_in", "/auth/login", "/accounts/login", "/signin.php"]
ADMIN_PATHS = ["/admin", "/administrator", "/admin/dashboard", "/manage"]

# regex
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUMERIC_RE = re.compile(r"^\d+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{8,}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# ----------------- HELPERS -----------------
def normalise_url(u):
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))

def same_domain(a, b):
    return urlparse(a).netloc == urlparse(b).netloc

def safe_get(session, url, **kwargs):
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        return e

def safe_post(session, url, data=None, **kwargs):
    try:
        return session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        return e

def detect_id_type(val):
    if val is None or val == "":
        return None
    v = val.strip()
    if UUID_RE.match(v):
        return "uuid"
    if NUMERIC_RE.match(v):
        return "numeric"
    if MD5_RE.match(v):
        return "md5"
    if SHA1_RE.match(v):
        return "sha1"
    if SHA256_RE.match(v):
        return "sha256"
    if BASE64_RE.match(v):
        return "base64-like"
    if len(v) <= 6 and v.isdigit():
        return "numeric"
    if len(v) >= 20:
        return "long-string"
    return "unknown"

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def response_sig(resp):
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    text = getattr(resp, "text", "") or ""
    return {"status": getattr(resp, "status_code", None), "len": len(text), "sample": text[:180]}

def login_success_heuristic(resp):
    if isinstance(resp, Exception):
        return False
    txt = getattr(resp, "text", "") or ""
    if resp.status_code in (302,):
        return True
    low = txt.lower()
    if "logout" in low or "sign out" in low or "dashboard" in low or "my account" in low:
        return True
    if resp.status_code == 200 and ("login" not in low and "signin" not in low):
        return True
    return False

# ----------------- DETECT LOGIN -----------------
def detect_login_candidates(target, session, logs):
    base = target.rstrip("/")
    candidates = []
    # check common paths
    for p in COMMON_LOGIN_PATHS:
        u = urljoin(base, p)
        logs.append(f"[detect] trying common path {u}")
        r = safe_get(session, u, headers=HEADERS)
        time.sleep(THROTTLE)
        if isinstance(r, Exception):
            logs.append(f"  - error {r}")
            continue
        text = getattr(r, "text", "") or ""
        if "password" in text.lower() or "sign in" in text.lower() or "log in" in text.lower():
            candidates.append((u, text))
            logs.append(f"  - login-like page found: {u}")
        else:
            # include as candidate anyway (some apps hide login behind JS)
            candidates.append((u, text))
    # parse root for forms with password field
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
    # dedupe
    seen=set(); uniq=[]
    for u,html_text in candidates:
        nu = normalise_url(u)
        if nu not in seen:
            seen.add(nu); uniq.append((u,html_text))
    return uniq

def inspect_form_html(html_text):
    soup = BeautifulSoup(html_text or "", "html.parser")
    inputs=[]
    csrf_fields={}
    auth_types=set()
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
    # fallback check placeholders / labels
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
        # links
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if href.startswith("javascript:") or href.startswith("#") or href.lower().startswith("mailto:"): continue
            full = urljoin(nu, href)
            if same_domain(base, full):
                fnu = normalise_url(full)
                found_urls.add(fnu)
                if fnu not in visited:
                    queue.append((full, d+1))
        # forms
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

# ----------------- ID GENERATORS -----------------
def gen_numeric(start, end):
    return [str(i) for i in range(start, end+1)]

def gen_uuids(n):
    return [str(uuid.uuid4()) for _ in range(n)]

def gen_base64_samples(n=3):
    out=[]
    for i in range(n):
        out.append((("user%d" % i).encode()).hex())
    return out

# ----------------- TEST SCENARIOS -----------------
def run_sequential_path(session, template, id_values, logs):
    findings=[]
    logs.append("[1] Sequential ID Tampering (Path)")
    for vid in id_values:
        url = template.replace("{id}", str(vid)) if "{id}" in template else template.rstrip("/") + "/" + str(vid)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        line = f"GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)"
        logs.append("  "+line)
        findings.append({"scenario":"sequential_path","target":url,"value":vid,"response":sig})
    return findings

def run_sequential_query(session, url_template, param, id_values, logs):
    findings=[]
    logs.append("[2] Sequential ID Tampering (Query Param)")
    parsed = urlparse(url_template)
    qs = parse_qs(parsed.query)
    for vid in id_values:
        qs[param]=[str(vid)]
        new_q = urlencode(qs, doseq=True)
        new_url = parsed._replace(query=new_q).geturl()
        r = safe_get(session, new_url, headers=HEADERS)
        sig = response_sig(r)
        line = f"GET {new_url} -> {sig.get('status')}"
        logs.append("  "+line)
        findings.append({"scenario":"sequential_query","target":new_url,"param":param,"value":vid,"response":sig})
    return findings

def run_hidden_field_tests(session, form, id_candidates, logs):
    findings=[]
    logs.append("[3] Hidden Field Manipulation (POST data)")
    action = form.get("action")
    post_data = {inp["name"]: inp.get("value","") for inp in form.get("inputs", [])}
    fields = [n for n in post_data.keys() if "id" in n.lower()]
    if not fields:
        fields = [n for n in post_data.keys()][:1] if post_data else []
    if not fields:
        logs.append("  - no postable id-like fields found")
        return findings
    for field in fields:
        for candidate in id_candidates:
            data = post_data.copy()
            data[field] = candidate
            r = safe_post(session, action, data=data, headers=HEADERS)
            sig = response_sig(r)
            logs.append(f"  POST {action} {field}={candidate} -> {sig.get('status')}")
            findings.append({"scenario":"hidden_post","action":action,"field":field,"value":candidate,"response":sig})
    return findings

def run_role_response_comparison(session, url_template, compare_ids, logs):
    findings=[]
    logs.append("[4] Role Response Comparison (self-check)")
    samples=[]
    for vid in compare_ids:
        url = url_template.replace("{id}",str(vid)) if "{id}" in url_template else urljoin(url_template, str(vid))
        r = safe_get(session, url, headers=HEADERS)
        txt = getattr(r,"text","") or ""
        samples.append((vid, txt))
        logs.append(f"  GET {url} -> {getattr(r,'status_code',None)} ({len(txt)} bytes)")
    if len(samples)>=2:
        a = samples[0][1]; b = samples[1][1]
        sim = similarity(a,b)
        logs.append(f"  Profile({samples[0][0]}) vs Profile({samples[1][0]}) similarity={sim:.2f}")
        findings.append({"scenario":"role_response_comparison","pairs":[(samples[0][0],samples[1][0])],"similarity":sim})
    return findings

def run_vertical_privilege(session, base_url, logs):
    findings=[]
    logs.append("[5] Vertical Privilege Escalation (/admin)")
    for p in ADMIN_PATHS:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {p} -> {sig.get('status')}")
        findings.append({"scenario":"vertical_admin","target":url,"response":sig})
    return findings

def run_horizontal_privilege(session, base_url, profile_template, id_values, logs):
    findings=[]
    logs.append("[6] Horizontal Privilege Escalation")
    for vid in id_values:
        url = profile_template.replace("{id}",str(vid)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{vid}")
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"horizontal_profile","target":url,"value":vid,"response":sig})
    return findings

# ----------------- HTML REPORT RENDERER -----------------
# --- PERUBAHAN 2: Menghapus nilai default untuk filename agar lebih eksplisit ---
def render_html_report(final_data, filename):
    # helper to badge types
    def badge_for(t):
        cls = "badge-unknown"
        txt = t or ""
        if t=="numeric": cls="badge-numeric"
        elif t=="uuid": cls="badge-uuid"
        elif t=="base64-like": cls="badge-base64"
        elif t in ("md5","sha1","sha256"): cls="badge-hash"
        elif t=="long-string": cls="badge-long"
        return f'<span class="badge {cls}">{html.escape(txt)}</span>'

    # build HTML
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    html_parts = []
    html_parts.append(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IDOR Report - {html.escape(final_data.get('url',''))}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{font-family:Inter,Segoe UI,Helvetica,Arial,sans-serif;background:#f4f6f8;color:#222;margin:0;padding:24px}}
  .card{{background:#fff;border-radius:10px;padding:18px;margin-bottom:18px;box-shadow:0 6px 18px rgba(24,39,75,0.06)}}
  h1{{
    margin:0 0 6px 0;font-size:20px;color:#0b2f5a
  }}
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
  .vuln{{background:#fff6f6;border-left:4px solid #ef4444;padding:8px;border-radius:6px}}
  .ok{{background:#f6fffa;border-left:4px solid #10b981;padding:8px;border-radius:6px}}
  .mono{{font-family:Menlo,monospace;font-size:13px;background:#0b1220;color:#dbeafe;padding:8px;border-radius:6px;white-space:pre-wrap;overflow:auto}}
  details{{margin-top:8px}}
  .scenario-title{{
    font-weight:600;margin:0 0 6px 0;font-size:15px;color:#0b3b61
  }}
  .small{{font-size:13px;color:#475569}}
  .btn{{display:inline-block;padding:8px 12px;background:#0ea5a4;color:#fff;border-radius:8px;text-decoration:none}}
</style>
</head><body>
<div class="card"><h1>Result — IDOR & Access Tests</h1>
<div class="muted">Target: {html.escape(final_data.get('url','-'))} &nbsp; • &nbsp; Generated: {now}</div>
</div>""")

    # Summary card
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
    html_parts.append(f'<div><strong>Auth type used</strong><div class="small">{html.escape(final_data.get("auth_type_used") or "-")}</div></div>')
    html_parts.append(f'<div><strong>Login success</strong><div class="small">{"Yes" if final_data.get("login_success") else "No"}</div></div>')
    html_parts.append('</div></div>')  # end summary card

    # Found IDs
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

    # Findings per scenario
    html_parts.append('<div class="card"><h2 class="scenario-title">Findings & Scenarios</h2>')
    findings = final_data.get("findings", [])
    if findings:
        # group by scenario
        # we'll render each finding as a sub-block; highlight responses with status 200 as suspicious
        for f in findings:
            scen = f.get("scenario") or f.get("action") or f.get("method") or "misc"
            # build header
            if f.get("scenario")=="sequential_path":
                header = f"Sequential Path — {html.escape(f.get('target',''))} (value={html.escape(str(f.get('value','-')) )})"
            elif f.get("scenario")=="sequential_query":
                header = f"Sequential Query — {html.escape(f.get('target',''))}"
            elif f.get("scenario")=="hidden_post":
                header = f"Hidden POST — {html.escape(f.get('action',''))} field {html.escape(f.get('field',''))}"
            elif f.get("scenario")=="role_response_comparison":
                header = f"Role Response Comparison — similarity {f.get('similarity'):.2f}"
            elif f.get("scenario")=="vertical_admin":
                header = f"Vertical Admin Check — {html.escape(f.get('target',''))}"
            elif f.get("scenario")=="horizontal_profile":
                header = f"Horizontal Profile — {html.escape(f.get('target',''))}"
            elif f.get("action")=="login_attempt":
                header = f"Login Attempt — method {html.escape(f.get('method','-'))}"
            else:
                header = html.escape(str(scen))
            resp = f.get("response", {})
            status = resp.get("status")
            sample = html.escape((resp.get("sample") or "")[:800])
            block_class = "ok" if status and status in (401,403,404) else "vuln"
            # if response contains error field, show error box
            if resp.get("error"):
                html_parts.append(f'<div class="vuln"><strong>{html.escape(header)}</strong><div class="small">Error: {html.escape(resp.get("error"))}</div></div>')
            else:
                html_parts.append(f'<div class="{block_class}" style="margin-bottom:10px;"><strong>{html.escape(header)}</strong>')
                html_parts.append(f'<div class="small">Status: {status} &nbsp; • &nbsp; Length: {resp.get("len")}</div>')
                # show sample collapsible
                html_parts.append(f'<details><summary class="small">View response sample</summary><div class="mono">{sample}</div></details>')
                html_parts.append('</div>')
    else:
        html_parts.append('<div class="muted">No findings recorded.</div>')
    html_parts.append('</div>')

    # Recommendations & logs
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

    # Logs
    html_parts.append('<div class="card"><h2 class="scenario-title">Execution Logs</h2>')
    logs = final_data.get("logs", [])
    if logs:
        # show logs in <pre>-like block
        safe_logs = "\n".join(html.escape(l) for l in logs)
        html_parts.append(f'<div class="mono">{safe_logs}</div>')
    else:
        html_parts.append('<div class="muted">No logs captured.</div>')
    html_parts.append('</div>')

    # meta footer
    meta = final_data.get("meta", {})
    html_parts.append(f'<div class="card"><div class="small">Tool meta: timeout={meta.get("timeout")}s • throttle={meta.get("throttle")}s • crawl_depth={meta.get("crawl_depth")}</div></div>')

    html_parts.append("</body></html>")

    html_content = "\n".join(html_parts)
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] Laporan HTML berhasil disimpan -> {filename}")
    except Exception as e:
        print(f"[-] Gagal menyimpan laporan HTML: {e}")

# ----------------- MAIN INTERACTIVE FLOW -----------------
def main():
    print("=== IDOR Full Flow (login -> crawl -> IDOR scenarios) ===")
    target = input("Target URL (contoh: http://127.0.0.1:5002): ").strip()
    if not target.startswith("http"):
        print("Masukkan URL lengkap (http/https). Exit.")
        return

    # --- PERUBAHAN 3: Meminta nama dasar untuk file laporan di awal ---
    report_base_name = input("Masukkan nama dasar untuk file laporan (contoh: report_website): ").strip()
    if not report_base_name:
        # Membuat nama default dari domain target jika input kosong
        try:
            domain_name = urlparse(target).netloc.replace('.', '_').replace(':', '_')
            report_base_name = f"idor_report_{domain_name}"
        except:
            report_base_name = "idor_report"
        print(f"Nama dasar tidak diisi, menggunakan default: '{report_base_name}'")

    html_report_filename = f"{report_base_name}.html"
    json_report_filename = f"{report_base_name}.json"
    # --- Akhir Perubahan 3 ---

    session = requests.Session()
    session.headers.update(HEADERS)
    output = {
        "url": target,
        "login_detected_paths": [],
        "auth_type_candidates": [],
        "login_path_used": None,
        "auth_type_used": None,
        "login_success": False,
        "found_urls": [],
        "found_forms": [],
        "found_ids": [],
        "findings": [],
        "errors": [],
        "recommendations": [],
        "logs": [],
        "meta": {"timeout": TIMEOUT, "throttle": THROTTLE, "crawl_depth": CRAWL_DEPTH}
    }

    # 1) detect login candidate(s)
    try:
        candidates = detect_login_candidates(target, session, output["logs"])
        output["login_detected_paths"] = [c[0] for c in candidates]
        for url, html_src in candidates:
            info = inspect_form_html(html_src)
            for a in info["auth_candidates"]:
                if a not in output["auth_type_candidates"]:
                    output["auth_type_candidates"].append(a)
            output["logs"].append(f"[detect] inspected {url} -> auth candidates {info['auth_candidates']}; csrf_keys={list(info['csrf'].keys())}")
    except Exception as e:
        output["errors"].append(f"Error detecting login: {e}")
        output["logs"].append(str(e))

    # 2) user selects auth mode
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

    # 3) ask credentials if chosen_mode
    cred_provided=False
    cred_mode_used=None
    if chosen_mode in ("email","username","both"):
        modes = [chosen_mode] if chosen_mode in ("email","username") else ["email","username"]
        for m in modes:
            ans = input(f"\nMasukkan credential untuk metode '{m}'? (y/n): ").strip().lower()
            if ans != "y":
                output["logs"].append(f"user skipped credentials for {m}")
                continue
            if m=="email":
                user = input("  Email: ").strip()
            else:
                user = input("  Username: ").strip()
            pwd = input("  Password: ").strip()
            login_url = output["login_detected_paths"][0] if output["login_detected_paths"] else urljoin(target, "/login")
            output["logs"].append(f"[login] attempting {m} -> {login_url} (credentials not saved to disk)")
            page = safe_get(session, login_url, headers=HEADERS)
            time.sleep(THROTTLE)
            form_info = {}
            if not isinstance(page, Exception):
                form_info = inspect_form_html(getattr(page,"text","") or "")
            payload = {}
            for k,v in form_info.get("csrf",{}).items():
                payload[k]=v
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
            resp = safe_post(session, action_post, data=payload, headers=HEADERS)
            sig = response_sig(resp)
            success = login_success_heuristic(resp)
            output["logs"].append(f"[login] POST {action_post} -> status {sig.get('status')} ; success={success}")
            output["findings"].append({"action":"login_attempt","method":m,"url":action_post,"success":bool(success),"response":sig})
            if success:
                print(f"[+] Login berhasil sebagai {user}")
                output["login_success"]=True
                output["login_path_used"]=action_post
                output["auth_type_used"]=m
                cred_provided=True
                cred_mode_used=m
                break
            else:
                print(f"[-] Login gagal untuk mode {m} (cek logs).")
                output["logs"].append(f"login attempt failed for {m}")
    else:
        output["logs"].append("No credentials provided / chosen. Proceeding as guest.")

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
    for u in urls:
        id_candidates.extend(detect_ids_in_url(u))
    for f in forms:
        id_candidates.extend(detect_ids_in_form(f))
    uniq=[]; seen=set()
    for it in id_candidates:
        key=(it.get("location"), it.get("url") or it.get("action"), it.get("param"), it.get("sample"))
        if key not in seen:
            seen.add(key); uniq.append(it)
    output["found_ids"]=uniq

    if uniq:
        print("\n[+] Terdeteksi identifier:")
        for it in uniq:
            print("    ", f"{it.get('location')} {it.get('url') or it.get('action')} -> {it.get('param')} = {it.get('sample')} ({it.get('type')})")
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

    # 6) Run scenarios
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
        output["logs"].append("No query param candidate for sequential query tests.")
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

    # Summarize & recommendations
    output["recommendations"].append("Review findings manually; heuristics can produce false positives.")
    if output["found_ids"]:
        output["recommendations"].append("Lakukan targeted IDOR tests pada identifier yang terdeteksi.")
    else:
        output["recommendations"].append("Jika tidak ada identifier, coba tingkatkan crawl depth atau gunakan Playwright untuk discover API/XHR.")

    # Final printing (console summary)
    print()
    print("[1] Sequential ID Tampering (Path)")
    for f in scen1:
        sig = f["response"]; print(f"  GET {f['target']} -> {sig.get('status')} ({sig.get('len')} bytes)")
    print()
    print("[2] Sequential ID Tampering (Query Param)")
    if scen2:
        for f in scen2: sig=f["response"]; print(f"  GET {f['target']} -> {sig.get('status')}")
    else:
        print("  (no candidate)")
    print()
    print("[3] Hidden Field Manipulation (POST data)")
    if scen3:
        for f in scen3: sig=f["response"]; print(f"  POST {f['action']} {f['field']}={f['value']} -> {sig.get('status')}")
    else:
        print("  (no postable forms found)")
    print()
    print("[4] Role Response Comparison (self-check)")
    for f in scen4: print(f"  similarity={f.get('similarity'):.2f}")
    print()
    print("[5] Vertical Privilege Escalation (/admin)")
    for f in scen5:
        sig=f["response"]; parsed=urlparse(f["target"]); path=parsed.path
        print(f"  GET {path} -> {sig.get('status')}")
    print()
    print("[6] Horizontal Privilege Escalation")
    for f in scen6:
        sig=f["response"]; print(f"  GET {f['target']} -> {sig.get('status')} ({sig.get('len')} bytes)")

    # build final structure
    final = {
        "url": output["url"],
        "login_detected_paths": output["login_detected_paths"],
        "auth_type_candidates": output["auth_type_candidates"],
        "login_path_used": output.get("login_path_used"),
        "auth_type_used": output.get("auth_type_used"),
        "login_success": output.get("login_success"),
        "found_urls_count": len(output.get("found_urls",[])),
        "found_forms_count": len(output.get("found_forms",[])),
        "found_ids": output.get("found_ids"),
        "findings": output.get("findings"),
        "errors": output.get("errors"),
        "recommendations": output.get("recommendations"),
        "logs": output.get("logs"),
        "meta": output.get("meta")
    }

    # --- PERUBAHAN 4: Menggunakan nama file yang sudah ditentukan di awal ---
    # Render HTML report
    render_html_report(final, html_report_filename)

    # Optionally save JSON too
    sv = input(f"\nSimpan hasil JSON ke file '{json_report_filename}'? (y/n): ").strip().lower()
    if sv=="y":
        try:
            with open(json_report_filename, "w", encoding="utf-8") as fh:
                json.dump(final, fh, indent=2, ensure_ascii=False)
            print(f"[+] Hasil JSON berhasil disimpan -> {json_report_filename}")
        except Exception as e:
            print(f"[-] Gagal menyimpan JSON: {e}")
    # --- Akhir Perubahan 4 ---

    print("\nSelesai. Ingat: jangan menyimpan kredensial di file; tool ini tidak menyimpan kredensial ke output.")

if __name__ == "__main__":
    main()
