#!/usr/bin/env python3
"""
idor_full_flow_html.py
Interactive single-file tool:
- Auto-detect login path & auth type (email/username)
- Ask credentials (if detected) and validate login
- On success: Crawl & list URLs/forms
- Detect ID types (numeric, uuid, base64-like, hash)
- Run 6 IDOR scenarios (see below) — upgraded to LEVEL 3 (advanced)
- Produce an HTML report (styled, collapsible, colored badges)
- Does NOT save credentials to disk or embed them in output
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re, json, time, uuid, sys, html, base64
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
    if getattr(resp, "status_code", None) in (302,):
        return True
    low = txt.lower()
    if "logout" in low or "sign out" in low or "dashboard" in low or "my account" in low:
        return True
    if getattr(resp, "status_code", None) == 200 and ("login" not in low and "signin" not in low):
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

# ----------------- LEVEL-3 HELPERS -----------------
def try_parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None

VOLATILE_KEYS = ["created_at","updated_at","timestamp","ts","expires_at","expiry","last_login","id_token","csrf_token"]
def normalize_json(obj):
    if isinstance(obj, dict):
        out = {}
        for k,v in obj.items():
            if any(vk in k.lower() for vk in VOLATILE_KEYS):
                continue
            out[k]=normalize_json(v)
        return out
    if isinstance(obj, list):
        return [normalize_json(x) for x in obj]
    return obj

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d")

COMMON_ADMIN_PATHS = ADMIN_PATHS + [
    "/admin/login","/admin-console","/manage/account","/cms","/dashboard/admin","/admin/api","/api/admin"
]

COMMON_GUESS_SUFFIXES = ["/orders/{}","/order/{}","/invoices/{}","/transactions/{}"]

# ----------------- UPGRADED LEVEL-3 SCENARIOS -----------------
def run_sequential_path(session, template, id_values, logs):
    findings=[]
    logs.append("[1] Sequential ID Tampering (Path) - LEVEL 3")
    # determine template form
    use_brace = "{id}" in template
    baseline = None
    tested = 0
    extra_limit = 20

    for vid in id_values:
        if use_brace:
            url = template.replace("{id}", str(vid))
        else:
            url = template.rstrip("/") + "/" + str(vid)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"sequential_path","target":url,"value":vid,"response":sig})
        tested += 1
        if baseline is None and not isinstance(r, Exception) and getattr(r,"status_code",None)==200:
            baseline = getattr(r,"text","") or ""

    # adaptive enumeration around numeric ids if applicable
    numeric_vals = []
    try:
        numeric_vals = [int(v) for v in id_values if NUMERIC_RE.match(str(v))]
    except Exception:
        numeric_vals = []
    if numeric_vals:
        max_found_200 = sum(1 for f in findings if f["response"].get("status")==200)
        if max_found_200 >= 2:
            lo = min(numeric_vals); hi = max(numeric_vals)
            extra_trials = []
            for d in range(1, extra_limit+1):
                extra_trials.append(lo - d)
                extra_trials.append(hi + d)
            for v in extra_trials:
                if v <= 0: continue
                url = template.replace("{id}", str(v)) if use_brace else template.rstrip("/") + "/" + str(v)
                r = safe_get(session, url, headers=HEADERS)
                sig = response_sig(r)
                logs.append(f"  [expand] GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
                findings.append({"scenario":"sequential_path_expand","target":url,"value":v,"response":sig})
                tested += 1
                if tested > (len(id_values) + 30):
                    break

    # content-aware diff: compare responses to baseline
    if baseline is not None:
        for f in findings:
            resp = f.get("response", {})
            if resp.get("status")!=200:
                continue
            sample = resp.get("sample","")
            sim = similarity(baseline[:2000], sample[:2000])
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
    base_url_noquery = parsed._replace(query=None).geturl()

    for vid in id_values:
        qs_local = dict(qs)
        qs_local[param]=[str(vid)]
        new_q = urlencode(qs_local, doseq=True)
        new_url = parsed._replace(query=new_q).geturl()
        r = safe_get(session, new_url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {new_url} -> {sig.get('status')}")
        findings.append({"scenario":"sequential_query","target":new_url,"param":param,"value":vid,"response":sig})

        # HTTP Parameter Pollution: duplicate param
        dup_q = f"{param}={qs_local[param][0]}&{param}={vid}"
        dup_url = base_url_noquery + "?" + dup_q
        r2 = safe_get(session, dup_url, headers=HEADERS)
        s2 = response_sig(r2)
        logs.append(f"  GET (HPP) {dup_url} -> {s2.get('status')}")
        findings.append({"scenario":"sequential_query_hpp","target":dup_url,"param":param,"value":vid,"response":s2})

        # method switching (POST)
        try:
            rpost = safe_post(session, base_url_noquery, data={param:str(vid)}, headers=HEADERS)
            sp = response_sig(rpost)
            logs.append(f"  POST {base_url_noquery} {param}={vid} -> {sp.get('status')}")
            findings.append({"scenario":"sequential_query_post","target":base_url_noquery,"param":param,"value":vid,"response":sp})
        except Exception as e:
            logs.append(f"  POST error: {e}")

        # mutations: padded, hex, base64
        mutations = []
        try:
            if NUMERIC_RE.match(str(vid)):
                mutations.append(str(vid).zfill(4))
                mutations.append(hex(int(vid))[2:])
            b64 = base64.b64encode(str(vid).encode()).decode()
            mutations.append(b64)
        except Exception:
            pass
        for m in [x for x in mutations if x]:
            qs_mut = dict(qs)
            qs_mut[param]=[m]
            mu = parsed._replace(query=urlencode(qs_mut,doseq=True)).geturl()
            rm = safe_get(session, mu, headers=HEADERS)
            sm = response_sig(rm)
            logs.append(f"  GET (mut) {mu} -> {sm.get('status')}")
            findings.append({"scenario":"sequential_query_mutation","target":mu,"param":param,"value":m,"response":sm})
    return findings

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

    # accept id_candidates as list of strings or list of dicts (from found_ids)
    id_pool = []
    for it in id_candidates:
        if isinstance(it, dict):
            v = it.get("sample")
            if v: id_pool.append(str(v))
        else:
            id_pool.append(str(it))
    id_pool.extend([str(i) for i in range(1,6)])  # small brute
    id_pool = list(dict.fromkeys(id_pool))

    for field in fields:
        for candidate in id_pool:
            data = post_data.copy()
            data[field] = candidate
            headers = HEADERS.copy()
            r = safe_post(session, action, data=data, headers=headers)
            sig = response_sig(r)
            logs.append(f"  POST {action} {field}={candidate} -> {sig.get('status')}")
            findings.append({"scenario":"hidden_post","action":action,"field":field,"value":candidate,"response":sig})
            # try JSON body if response looks like API or guessed
            ct = getattr(r, "headers", {}) or {}
            ct_val = ""
            if isinstance(ct, dict):
                for hk in ct:
                    if hk.lower() == "content-type":
                        ct_val = ct[hk]
                        break
            if "application/json" in ct_val or try_parse_json((getattr(r,"text","") or "")) is not None:
                headers_json = HEADERS.copy()
                headers_json["Content-Type"]="application/json"
                try:
                    rj = safe_post(session, action, data=json.dumps(data), headers=headers_json)
                    sj = response_sig(rj)
                    logs.append(f"  POST(JSON) {action} {field}={candidate} -> {sj.get('status')}")
                    findings.append({"scenario":"hidden_post_json","action":action,"field":field,"value":candidate,"response":sj})
                except Exception as e:
                    logs.append(f"  POST(JSON) error: {e}")

    # try alternate content types
    for field in fields:
        for candidate in id_pool[:3]:
            headers_alt = HEADERS.copy()
            headers_alt["Content-Type"]="application/x-www-form-urlencoded; charset=UTF-8"
            ralt = safe_post(session, action, data={field:candidate}, headers=headers_alt)
            salt = response_sig(ralt)
            logs.append(f"  POST(alt-ct) {action} {field}={candidate} -> {salt.get('status')}")
            findings.append({"scenario":"hidden_post_altct","action":action,"field":field,"value":candidate,"response":salt})

    return findings

def run_role_response_comparison(session, url_template, compare_ids, logs):
    findings=[]
    logs.append("[4] Role Response Comparison - LEVEL 3")
    samples=[]
    for vid in compare_ids:
        url = url_template.replace("{id}",str(vid)) if "{id}" in url_template else urljoin(url_template, str(vid))
        r = safe_get(session, url, headers=HEADERS)
        txt = getattr(r,"text","") or ""
        samples.append((vid, txt, response_sig(r)))
        logs.append(f"  GET {url} -> {getattr(r,'status_code',None)} ({len(txt)} bytes)")

    if len(samples)>=2:
        a = samples[0][1]; b = samples[1][1]
        sim = similarity(a,b)
        ja = try_parse_json(a); jb = try_parse_json(b)
        json_diff = None
        if ja is not None and jb is not None:
            na = normalize_json(ja); nb = normalize_json(jb)
            keys_a = set(na.keys()) if isinstance(na, dict) else set()
            keys_b = set(nb.keys()) if isinstance(nb, dict) else set()
            added = list(keys_b - keys_a)
            removed = list(keys_a - keys_b)
            json_diff = {"added_keys": added, "removed_keys": removed}
            logs.append(f"  JSON diff -> added:{added} removed:{removed}")
        combined = a + "\n" + b
        emails = list(set(EMAIL_RE.findall(combined)))
        phones = list(set(PHONE_RE.findall(combined)))
        findings.append({"scenario":"role_response_comparison","pairs":[(samples[0][0],samples[1][0])],"similarity":sim,"json_diff":json_diff,"emails":emails,"phones":phones,"response":{}})
        logs.append(f"  similarity={sim:.2f} ; emails_found={len(emails)} phones_found={len(phones)}")
    return findings

def run_vertical_privilege(session, base_url, logs):
    findings=[]
    logs.append("[5] Vertical Privilege Escalation (/admin) - LEVEL 3")
    for p in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {p} -> {sig.get('status')}")
        findings.append({"scenario":"vertical_admin","target":url,"response":sig})
        # header probes (log-only)
        probe_headers = [
            {"X-Original-URL": p},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": urlparse(base_url).netloc},
        ]
        for hh in probe_headers:
            try:
                rh = safe_get(session, url, headers={**HEADERS, **hh})
                sh = response_sig(rh)
                logs.append(f"    header-probe {list(hh.keys())[0]} -> {sh.get('status')}")
                findings.append({"scenario":"vertical_admin_header_probe","target":url,"headers":hh,"response":sh})
            except Exception as e:
                logs.append(f"    header-probe error: {e}")
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
        # nested resource guesses
        for sfx in COMMON_GUESS_SUFFIXES:
            guess = urljoin(base_url, sfx.format(vid))
            rg = safe_get(session, guess, headers=HEADERS)
            sg = response_sig(rg)
            logs.append(f"    GET {guess} -> {sg.get('status')}")
            findings.append({"scenario":"horizontal_nested_guess","target":guess,"value":vid,"response":sg})
    # semantic compare between first two ids if available
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

def run_level3_advanced_tests(session, base_url, id_info, logs):
    """
    Orchestrator for Level-3 advanced tests.
    id_info: list of dicts like {"location": "...", "url": "...", "param": ..., "sample": ..., "type": ...}
    """
    findings=[]
    logs.append("[L3] Starting Level-3 advanced orchestration")
    numeric_ids = []
    profile_template = None
    # gather samples & try to build profile template
    for it in id_info:
        if it.get("type")=="numeric":
            try:
                numeric_ids.append(int(it.get("sample")))
            except Exception:
                pass
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

    # build id pool
    id_pool = [str(i) for i in (numeric_ids if numeric_ids else [1,2,3,4,5])]
    id_pool += [str(uuid.uuid4()) for _ in range(3)]
    id_pool = list(dict.fromkeys(id_pool))

    # run sequential path with expanded pool
    findings += run_sequential_path(session, profile_template, id_pool, logs)

    # pick a query candidate if any in id_info
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

    # hidden field tests — try using id_info samples as candidates
    for it in id_info:
        if it.get("location")=="form":
            try:
                findings.extend(run_hidden_field_tests(session, {"action":it.get("action"), "inputs":[{"name":it.get("param"), "type":"text", "value":it.get("sample")}]}, [it], logs))
            except Exception as e:
                logs.append(f"  [l3] hidden test error: {e}")

    # base64 decode/try
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

    # uuid mutation
    for s in id_info:
        if s.get("type")=="uuid":
            try:
                orig = s.get("sample")
                muts = [str(uuid.uuid4()) for _ in range(4)]
                findings += run_sequential_path(session, profile_template, muts, logs)
            except Exception:
                pass
            break

    # timing probe: compare two ids latency
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
        for f in findings:
            scen = f.get("scenario") or f.get("action") or f.get("method") or "misc"
            if f.get("scenario")=="sequential_path":
                header = f"Sequential Path — {html.escape(f.get('target',''))} (value={html.escape(str(f.get('value','-')) )})"
            elif f.get("scenario")=="sequential_query":
                header = f"Sequential Query — {html.escape(f.get('target',''))}"
            elif f.get("scenario")=="hidden_post":
                header = f"Hidden POST — {html.escape(f.get('action',''))} field {html.escape(f.get('field',''))}"
            elif f.get("scenario")=="role_response_comparison":
                sim = f.get("similarity")
                if sim is not None:
                    header = f"Role Response Comparison — similarity {sim:.2f}"
                else:
                    header = "Role Response Comparison"
            elif f.get("scenario")=="vertical_admin":
                header = f"Vertical Admin Check — {html.escape(f.get('target',''))}"
            elif f.get("scenario")=="horizontal_profile":
                header = f"Horizontal Profile — {html.escape(f.get('target',''))}"
            elif f.get("action")=="login_attempt":
                header = f"Login Attempt — method {html.escape(f.get('method','-'))}"
            else:
                header = html.escape(str(scen))
            resp = f.get("response", {}) or {}
            status = resp.get("status")
            sample = html.escape((resp.get("sample") or "")[:800])
            block_class = "ok" if status and status in (401,403,404) else "vuln"
            if resp.get("error"):
                html_parts.append(f'<div class="vuln"><strong>{html.escape(header)}</strong><div class="small">Error: {html.escape(resp.get("error"))}</div></div>')
            else:
                html_parts.append(f'<div class="{block_class}" style="margin-bottom:10px;"><strong>{html.escape(header)}</strong>')
                html_parts.append(f'<div class="small">Status: {status} &nbsp; • &nbsp; Length: {resp.get("len")}</div>')
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

    # 6) Run scenarios (upgraded level-3 implementations)
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

    # Level-3 orchestrator: additional advanced tests & chaining
    try:
        scen_l3 = run_level3_advanced_tests(session, target, output["found_ids"], output["logs"])
        output["findings"].extend(scen_l3)
    except Exception as e:
        output["logs"].append(f"[l3] orchestrator error: {e}")

    # --- SANITIZE: pastikan setiap finding punya 'response' key supaya tidak crash di akhir ---
    for f in output["findings"]:
        if 'response' not in f:
            f['response'] = {}

    # Summarize & recommendations
    output["recommendations"].append("Review findings manually; heuristics can produce false positives.")
    if output["found_ids"]:
        output["recommendations"].append("Lakukan targeted IDOR tests pada identifier yang terdeteksi.")
    else:
        output["recommendations"].append("Jika tidak ada identifier, coba tingkatkan crawl depth atau gunakan Playwright untuk discover API/XHR.")

    # Final printing (console summary) — defensive access to fields
    def _print_resp_short(f):
        resp = f.get("response", {}) or {}
        status = resp.get("status")
        length = resp.get("len")
        target = f.get("target") or f.get("action") or f.get("url") or "-"
        scen = f.get("scenario") or "-"
        if scen in ("timing_probe",):
            print(f"  timing_probe targets={f.get('targets')} times={f.get('times')}")
            return
        if scen in ("timing_anomaly",):
            print(f"  timing_anomaly details={f.get('details')}")
            return
        if scen == "role_response_comparison":
            sim = f.get("similarity")
            pairs = f.get("pairs")
            print(f"  role_response_comparison pairs={pairs} similarity={sim}")
            return
        if status is None and length is None:
            # fallback: print minimal summary
            print(f"  {scen} -> {json.dumps({k:v for k,v in f.items() if k!='response'})[:200]}")
            return
        if length is None:
            print(f"  GET {target} -> status={status}")
        else:
            print(f"  GET {target} -> {status} ({length} bytes)")

    print()
    print("[1] Sequential ID Tampering (Path)")
    for f in scen1:
        _print_resp_short(f)
    print()
    print("[2] Sequential ID Tampering (Query Param)")
    if scen2:
        for f in scen2:
            _print_resp_short(f)
    else:
        print("  (no candidate)")
    print()
    print("[3] Hidden Field Manipulation (POST data)")
    if scen3:
        for f in scen3:
            resp = f.get("response", {}) or {}
            status = resp.get("status")
            action = f.get("action") or "-"
            field = f.get("field") or "-"
            value = f.get("value") or "-"
            print(f"  POST {action} {field}={value} -> {status}")
    else:
        print("  (no postable forms found)")
    print()
    print("[4] Role Response Comparison (self-check)")
    if scen4:
        for f in scen4:
            sim = f.get("similarity")
            if sim is not None:
                print(f"  similarity={sim:.2f}")
            else:
                print(f"  {f}")
    else:
        print("  (no comparisons)")
    print()
    print("[5] Vertical Privilege Escalation (/admin)")
    for f in scen5:
        resp = f.get("response", {}) or {}
        status = resp.get("status")
        parsed = urlparse(f.get("target") or "-")
        path = parsed.path
        print(f"  GET {path} -> {status}")
    print()
    print("[6] Horizontal Privilege Escalation")
    for f in scen6:
        resp = f.get("response", {}) or {}
        status = resp.get("status")
        targ = f.get("target") or "-"
        length = resp.get("len")
        if length is not None:
            print(f"  GET {targ} -> {status} ({length} bytes)")
        else:
            print(f"  GET {targ} -> {status}")

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
