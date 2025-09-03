#!/usr/bin/env python3
"""
UWSF - Unified Web Security Framework (single-file)

Single-file interactive prototype:
- Crawl & discover pages (heuristic login detection)
- Manual login (prompt Email/Username + hidden Password)
- Safe bruteforce (wordlist user:pass, limited attempts)
- Identifier detection (path, query, hidden, JSON)
- IDOR tests (sequential path, query, HPP, mutated IDs, hidden-field manipulation)
- Privilege escalation tests (admin paths, header spoofing)
- Business-logic probes (price probe, checkout step)
- JSON + HTML reporting and artifacts (cookies + raw responses)
- Legal confirmation at start (required)
- Hidden-field POST requires explicit confirmation before executing

Author: Senior Security Engineer (prototype)
"""

import sys
import os
import re
import json
import time
import uuid
import html
import getpass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque, defaultdict
from difflib import SequenceMatcher

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    print("Missing dependencies: pip install requests beautifulsoup4")
    sys.exit(1)

# ----------------------------- Config / Defaults -----------------------------
DEFAULT_CRAWL_DEPTH = 2
DEFAULT_MAX_PAGES = 200
DEFAULT_DELAY = 0.8
SIMILARITY_THRESHOLD = 0.85
ID_TEST_WINDOW = 2  # neighbor IDs to test (e.g., +/- 1..2)
REPORTS_DIR = "reports"
ARTIFACTS_DIR = "artifacts"

# ----------------------------- Utilities -------------------------------------
def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def make_scan_id():
    return f"uwsf-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

def sane_filename(s):
    return re.sub(r"[^a-zA-Z0-9_.-]", "-", s)

def short(text, n=300):
    t = (text or '').strip().replace("\r", "").replace("\n", " ")
    return t[:n] + ("..." if len(t) > n else "")

def norm_html_text(html_text):
    s = re.sub(r"\b\d{2}:\d{2}:\d{2}\b", "", (html_text or ''))
    s = re.sub(r"[0-9a-fA-F]{20,}", "", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def similarity(a, b):
    a2 = norm_html_text(a or '')
    b2 = norm_html_text(b or '')
    if not a2 or not b2:
        return 0.0
    return SequenceMatcher(None, a2, b2).ratio()

def is_uuid(s):
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False

def is_base64_like(s):
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]{6,}", (s or ''))) and ("=" in (s or ''))

# ----------------------------- Logger ----------------------------------------
class Logger:
    def __init__(self):
        self.rows = []

    def _add(self, level, msg, echo=True):
        t = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        line = f"[{level}] {t} - {msg}"
        self.rows.append(line)
        if echo:
            print(line)

    def info(self, msg): self._add("INFO", msg)
    def debug(self, msg): self._add("DEBUG", msg, echo=False)
    def warn(self, msg): self._add("WARN", msg)

# ----------------------------- Crawler ---------------------------------------
class WebCrawler:
    def __init__(self, base_url, session=None, logger=None, max_pages=DEFAULT_MAX_PAGES, delay=DEFAULT_DELAY):
        self.base = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.delay = delay
        self.logger = logger or Logger()

    def same_origin(self, url):
        try:
            return urlparse(url).netloc == urlparse(self.base).netloc
        except Exception:
            return False

    def get(self, url):
        try:
            r = self.session.get(url, timeout=15, allow_redirects=True)
            time.sleep(self.delay)
            return r
        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            return None

    def crawl(self, depth=DEFAULT_CRAWL_DEPTH):
        self.logger.info(f"[+] Crawling halaman untuk menemukan link/form... (base={self.base}, depth={depth})")
        visited = set()
        pages = {}
        q = deque()
        q.append((self.base, 0))
        while q and len(visited) < self.max_pages:
            url, d = q.popleft()
            if url in visited or d > depth:
                continue
            r = self.get(url)
            visited.add(url)
            if not r:
                continue
            pages[url] = r
            try:
                soup = BeautifulSoup(r.text or '', 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href'].strip()
                    if href.startswith('mailto:') or href.startswith('tel:'):
                        continue
                    abs_link = urljoin(url, href)
                    if self.same_origin(abs_link) and abs_link not in visited:
                        q.append((abs_link, d+1))
                for s in soup.find_all('script', src=True):
                    src = urljoin(url, s['src'])
                    if self.same_origin(src) and src not in pages:
                        r_js = self.get(src)
                        if r_js:
                            pages[src] = r_js
            except Exception as e:
                self.logger.debug(f"Parsing error for {url}: {e}")
        self.logger.info(f"[+] Crawl selesai. Halaman ditemukan: {len(pages)}")
        return pages

# ----------------------------- Login Detection -------------------------------
class LoginDetector:
    KEYWORDS = ['login','signin','auth','session','account','masuk','sign-in']
    def __init__(self, logger=None):
        self.logger = logger or Logger()

    def score_page(self, url, response):
        score = 0.0
        reasons = []
        try:
            text = response.text or ''
            soup = BeautifulSoup(text, 'html.parser')
            # forms with password
            forms = soup.find_all('form')
            for form in forms:
                if form.find('input', {'type': 'password'}):
                    score += 0.5
                    reasons.append('password_input')
                    if form.find('input', {'name': re.compile(r'user|email|login', re.I)}):
                        score += 0.2
                        reasons.append('username_field')
            p = urlparse(url)
            for kw in self.KEYWORDS:
                if kw in p.path.lower(): 
                    score += 0.15; reasons.append('url_keyword')
                if soup.title and soup.title.string and kw in soup.title.string.lower():
                    score += 0.1; reasons.append('title_keyword')
            if re.search(r"\b(api|auth|login|signin)[\w/\-\.]*\b", text, re.I):
                score += 0.05; reasons.append('js_api_like')
        except Exception as e:
            self.logger.debug(f"Score error {url}: {e}")
        return min(score, 1.0), list(set(reasons))

    def detect(self, pages):
        candidates = []
        for url, resp in pages.items():
            sc, reasons = self.score_page(url, resp)
            if sc > 0:
                candidates.append({'url': url, 'score': sc, 'reasons': reasons, 'response': resp})
        candidates.sort(key=lambda x: x['score'], reverse=True)
        return candidates

    def extract_auth_types(self, response):
        types = set()
        try:
            soup = BeautifulSoup(response.text or '', 'html.parser')
            form = None
            for f in soup.find_all('form'):
                if f.find('input', {'type':'password'}):
                    form = f; break
            if not form:
                return ['unknown']
            for inp in form.find_all('input'):
                name = (inp.get('name') or '').lower()
                itype = (inp.get('type') or '').lower()
                if 'email' in name or itype == 'email':
                    types.add('email')
                if any(k in name for k in ('user','username','login')):
                    types.add('username')
            if not types:
                types.add('unknown')
        except Exception as e:
            self.logger.debug(f"extract_auth_types: {e}")
            types.add('unknown')
        return list(types)

# ----------------------------- Auth Manager ----------------------------------
class AuthManager:
    def __init__(self, session=None, logger=None):
        self.session = session or requests.Session()
        self.logger = logger or Logger()

    def extract_form(self, response):
        try:
            soup = BeautifulSoup(response.text or '', 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                if form.find('input', {'type':'password'}):
                    return form
            return forms[0] if forms else None
        except Exception as e:
            self.logger.debug(f"extract_form: {e}")
            return None

    def build_payload(self, form, username, password):
        payload = {}
        action = form.get('action') if form else None
        method = (form.get('method') or 'post').lower() if form else 'post'
        for inp in form.find_all('input') if form else []:
            name = inp.get('name') or inp.get('id')
            if not name:
                continue
            itype = (inp.get('type') or '').lower()
            if itype == 'password':
                payload[name] = password
            elif itype in ('text','email'):
                payload[name] = username
            else:
                payload[name] = inp.get('value', '')
        return action, method, payload

    def try_login_once(self, login_url, username, password):
        try:
            r = self.session.get(login_url, timeout=15)
            time.sleep(DEFAULT_DELAY)
        except Exception as e:
            self.logger.debug(f"try_login_once GET failed {login_url}: {e}")
            return False, None
        form = self.extract_form(r)
        if not form:
            data = {'username': username, 'user': username, 'email': username, 'password': password, 'pass': password}
            try:
                rp = self.session.post(login_url, data=data, timeout=15)
                time.sleep(DEFAULT_DELAY)
            except Exception as e:
                self.logger.debug(f"fallback post failed: {e}")
                return False, None
            return (self.validate_session(rp), rp)
        action, method, payload = self.build_payload(form, username, password)
        action_url = urljoin(login_url, action) if action else login_url
        try:
            if method == 'post':
                rp = self.session.post(action_url, data=payload, timeout=15)
            else:
                rp = self.session.get(action_url, params=payload, timeout=15)
            time.sleep(DEFAULT_DELAY)
        except Exception as e:
            self.logger.debug(f"login submit failed: {e}")
            return False, None
        return (self.validate_session(rp), rp)

    def validate_session(self, resp):
        try:
            if resp is None:
                return False
            cookies = self.session.cookies
            if cookies and len(cookies) > 0:
                try:
                    r = self.session.get(resp.url, timeout=10)
                    if r and any(k in (r.text or '').lower() for k in ('logout','sign out','dashboard','profile')):
                        return True
                except Exception:
                    return True
            if resp.history and len(resp.history) > 0:
                return True
            if 200 <= resp.status_code < 400 and 'incorrect' not in (resp.text or '').lower():
                return True
        except Exception as e:
            self.logger.debug(f"validate_session exception: {e}")
        return False

    # ---- Manual login: prompts separate fields and hides password ----
    def login_manual(self, login_url, method_hint=None):
        prompt_user = 'User'
        if method_hint == 'email':
            prompt_user = 'Email'
        elif method_hint == 'username':
            prompt_user = 'Username'
        print()
        user = input(f"  > {prompt_user}: ").strip()
        if not user:
            self.logger.warn("No user provided; aborting manual login.")
            return False, None, None
        pwd = getpass.getpass("  > Password (input hidden): ")
        if not pwd:
            self.logger.warn("No password provided; aborting manual login.")
            return False, None, None
        self.logger.info(f"[+] Mencoba login sebagai {user}:****")
        ok, resp = self.try_login_once(login_url, user, pwd)
        if ok:
            self.logger.info(f"[+] Login berhasil sebagai {user} (terverifikasi).")
            return True, {'user': user, 'pass': '***'}, resp
        else:
            self.logger.warn(f"[!] Login manual gagal untuk: {user}")
            return False, None, resp

    # ---- Safe bruteforce using wordlist user:pass ----
    def login_bruteforce(self, login_url):
        print()
        path = input("Masukkan path ke wordlist (format each line user:pass): ").strip()
        if not path or not os.path.exists(path):
            self.logger.warn("File wordlist tidak ditemukan.")
            return False, None, None
        confirm = input("Bruteforce safe-mode: delay tiap percobaan & max 200 attempts. Lanjutkan? (y/n): ").strip().lower()
        if confirm != 'y':
            self.logger.info("Bruteforce dibatalkan oleh user.")
            return False, None, None
        attempts = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if attempts >= 200:
                    self.logger.warn("Reached max safe attempts (200).")
                    break
                line = line.strip()
                if not line or ':' not in line:
                    continue
                user, pwd = line.split(':', 1)
                attempts += 1
                self.logger.debug(f"[brute] try {attempts} -> {user}:****")
                ok, resp = self.try_login_once(login_url, user, pwd)
                if ok:
                    self.logger.info(f"[+] Bruteforce success: {user}:****")
                    return True, {'user': user, 'pass': '***'}, resp
        self.logger.warn("[!] Bruteforce finished without success.")
        return False, None, None

# ----------------------------- Identifier Detection --------------------------
class IdentifierDetector:
    RE_NUM = re.compile(r"/([0-9]{1,10})(?:[/?#]|$)")
    RE_QUERY_ID = re.compile(r"\b(id|uid|user_id|order_id|invoice_id|ref)\b", re.I)
    def __init__(self, logger=None):
        self.logger = logger or Logger()

    def scan_pages(self, pages):
        identifiers = []
        for url, resp in pages.items():
            for m in self.RE_NUM.finditer(url):
                sample = m.group(1)
                identifiers.append({'location':'path','url':url,'param':None,'sample':sample,'type':'numeric'})
            q = urlparse(url).query
            if q:
                qs = parse_qs(q)
                for k, vals in qs.items():
                    if self.RE_QUERY_ID.search(k):
                        for v in vals:
                            t = 'unknown'
                            if v.isdigit(): t = 'numeric'
                            elif is_uuid(v): t = 'uuid'
                            elif is_base64_like(v): t = 'base64'
                            identifiers.append({'location':'query','url':url,'param':k,'sample':v,'type':t})
            try:
                js = resp.json()
                def walk(obj):
                    if isinstance(obj, dict):
                        for k,v in obj.items():
                            if self.RE_QUERY_ID.search(k) and isinstance(v,(str,int)):
                                val = str(v)
                                t = 'numeric' if val.isdigit() else 'uuid' if is_uuid(val) else 'base64' if is_base64_like(val) else 'string'
                                identifiers.append({'location':'json','url':url,'param':k,'sample':val,'type':t})
                            else:
                                walk(v)
                    elif isinstance(obj, list):
                        for it in obj: walk(it)
                walk(js)
            except Exception:
                pass
            try:
                soup = BeautifulSoup(resp.text or '', 'html.parser')
                for hidden in soup.find_all('input', {'type':'hidden'}):
                    name = hidden.get('name') or hidden.get('id')
                    val = hidden.get('value','')
                    if name and val:
                        t = 'numeric' if val.isdigit() else 'uuid' if is_uuid(val) else 'base64' if is_base64_like(val) else 'string'
                        identifiers.append({'location':'hidden','url':url,'param':name,'sample':val,'type':t})
            except Exception:
                pass
        # dedupe
        seen = set(); out=[]
        for i in identifiers:
            key=(i.get('url'), i.get('param'), i.get('sample'))
            if key in seen: continue
            seen.add(key); out.append(i)
        return out

# ----------------------------- IDOR Tester ------------------------------------
class IDORTester:
    def __init__(self, session, logger=None):
        self.session = session
        self.logger = logger or Logger()
        self.findings = []
        self.raw_responses = {}  # store raw responses for artifacts

    def test_numeric_path(self, url, sample, test_range=None):
        try:
            orig = self.session.get(url, timeout=15)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        orig_text = orig.text or ''
        self.raw_responses[url] = orig_text
        if not test_range:
            try:
                num = int(sample)
                test_ids = []
                for d in range(1, ID_TEST_WINDOW+1):
                    test_ids.extend([str(num + d), str(max(1, num - d))])
            except Exception:
                test_ids = []
        else:
            test_ids = [str(x) for x in test_range]
        for tid in test_ids:
            test_url = url.replace(f"/{sample}", f"/{tid}")
            try:
                r = self.session.get(test_url, timeout=12)
                time.sleep(DEFAULT_DELAY)
            except Exception:
                continue
            self.raw_responses[test_url] = r.text or ''
            sim = similarity(orig_text, r.text or '')
            status = getattr(r, 'status_code', None)
            if sim >= SIMILARITY_THRESHOLD:
                self.findings.append({'scenario':'sequential_path','url':test_url,'status':status,'marker':'OK','note':f"Status {status}"})
            else:
                lower = (r.text or '').lower()
                if re.search(r"\b(email|password|ssn|card|account|username|id)\b", lower):
                    self.findings.append({'scenario':'sequential_path','url':test_url,'status':status,'marker':'!!','note':'Potential IDOR (User data exposed)','severity':'high','evidence':short(r.text,800)})
                else:
                    self.findings.append({'scenario':'sequential_path','url':test_url,'status':status,'marker':'!!','note':'Potential IDOR (low evidence)','severity':'medium','evidence':short(r.text,400)})

    def test_query_param(self, url, param, sample):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param not in qs:
            return
        try:
            orig = self.session.get(url, timeout=15)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        orig_text = orig.text or ''
        self.raw_responses[url] = orig_text
        test_vals = []
        if sample.isdigit():
            num = int(sample)
            for d in range(1, ID_TEST_WINDOW+2):
                test_vals.extend([str(num + d), str(max(1, num - d))])
        else:
            test_vals = ['0002','1','2', sample[::-1]]
        # HPP test: multiple parameters
        multi_test_q = parsed._replace(query="&".join([f"{param}={test_vals[0]}", f"{param}={test_vals[1]}"])).geturl() if len(test_vals) >= 2 else None
        if multi_test_q:
            try:
                r_multi = self.session.get(multi_test_q, timeout=12)
                time.sleep(DEFAULT_DELAY)
                sim_multi = similarity(orig_text, r_multi.text or '')
                if sim_multi < SIMILARITY_THRESHOLD:
                    self.findings.append({'scenario':'sequential_query','url':multi_test_q,'status':getattr(r_multi,'status_code',None),'marker':'!!','note':'HPP detected (Multiple ID params accepted)','severity':'high','evidence':short(r_multi.text,400)})
            except Exception:
                pass
        for v in test_vals:
            new_qs = qs.copy(); new_qs[param] = [v]
            new_q = '&'.join([f"{k}={new_qs[k][0]}" for k in new_qs])
            test_url = parsed._replace(query=new_q).geturl()
            try:
                r = self.session.get(test_url, timeout=12)
                time.sleep(DEFAULT_DELAY)
            except Exception:
                continue
            self.raw_responses[test_url] = r.text or ''
            sim = similarity(orig_text, r.text or '')
            status = getattr(r,'status_code', None)
            if sim >= SIMILARITY_THRESHOLD:
                self.findings.append({'scenario':'sequential_query','url':test_url,'status':status,'marker':'OK','note':f"Status {status}"})
            else:
                lower = (r.text or '').lower()
                if v.startswith('0') and sim < SIMILARITY_THRESHOLD:
                    # mutated (padding) accepted
                    self.findings.append({'scenario':'sequential_query','url':test_url,'status':status,'marker':'!!','note':'Mutated ID accepted (Padding bypass)','severity':'high','evidence':short(r.text,400)})
                elif re.search(r"\b(email|order|card|account|username|id)\b", lower):
                    self.findings.append({'scenario':'sequential_query','url':test_url,'status':status,'marker':'!!','note':'Potential IDOR (Order data exposed)','severity':'high','evidence':short(r.text,800)})
                else:
                    self.findings.append({'scenario':'sequential_query','url':test_url,'status':status,'marker':'!!','note':'Potential IDOR (low evidence)','severity':'medium','evidence':short(r.text,400)})

    def test_hidden_fields(self, url, param, sample):
        # We will present the POST action and ask user confirmation before executing ANY POST
        try:
            r = self.session.get(url, timeout=12)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        try:
            soup = BeautifulSoup(r.text or '', 'html.parser')
            target_forms = []
            for form in soup.find_all('form'):
                hidden = form.find('input', {'name': param})
                if hidden:
                    action = form.get('action') or url
                    method = (form.get('method') or 'post').lower()
                    target_forms.append((form, action, method))
        except Exception:
            target_forms = []
        if not target_forms:
            return
        # present each form action and ask for confirmation to mutate hidden param
        for form, action, method in target_forms:
            action_url = urljoin(url, action)
            print("\nPOST", action_url)
            print(f"    Hidden Param: {param} = {sample}")
            confirm = input("    Konfirmasi: akan mengirim POST yang memodifikasi hidden param. Lanjutkan? (y/n): ").strip().lower()
            if confirm != 'y':
                self.logger.info("    Skip hidden-field manipulation as user declined.")
                continue
            # prepare payload and submit original then mutated
            payload = {}
            for inp in form.find_all('input'):
                name = inp.get('name') or inp.get('id')
                if not name:
                    continue
                itype = (inp.get('type') or '').lower()
                if itype == 'password':
                    payload[name] = "DUMMY_PASS"
                elif itype == 'hidden':
                    payload[name] = inp.get('value', '')
                elif itype in ('text','email'):
                    payload[name] = inp.get('value','')
                else:
                    payload[name] = inp.get('value','')
            # attempt original (as-is)
            try:
                r_orig = self.session.post(action_url, data=payload, timeout=15) if method=='post' else self.session.get(action_url, params=payload, timeout=15)
                time.sleep(DEFAULT_DELAY)
            except Exception:
                r_orig = None
            note_orig = "[OK] Allowed for current user" if r_orig and 200 <= getattr(r_orig,'status_code',0) < 400 else "[OK] Request returned non-error"
            print(f"    Hidden Param: {param} -> {note_orig}")
            # mutated
            payload_mut = payload.copy()
            # choose mutated value: sample+1 if numeric else sample+'_MUT'
            if sample.isdigit():
                try:
                    mutated = str(int(sample) + 1)
                except Exception:
                    mutated = sample + "_M"
            else:
                mutated = sample + "_M"
            payload_mut[param] = mutated
            try:
                r_mut = self.session.post(action_url, data=payload_mut, timeout=15) if method=='post' else self.session.get(action_url, params=payload_mut, timeout=15)
                time.sleep(DEFAULT_DELAY)
            except Exception:
                r_mut = None
            if r_mut:
                # compare responses
                sim = similarity((r_orig.text if r_orig else ''), r_mut.text or '')
                if sim < SIMILARITY_THRESHOLD:
                    print(f"    Hidden Param: {param} -> [!!] Potential IDOR (Modified hidden input accepted)")
                    self.findings.append({'scenario':'hidden_field','url':action_url,'param':param,'original':short(r_orig.text if r_orig else ''),'mutated':short(r_mut.text),'marker':'!!','note':'Potential IDOR (Modified hidden input accepted)','severity':'medium','evidence':short(r_mut.text,400)})
                    self.raw_responses[action_url + "#mutated"] = r_mut.text or ''
                else:
                    print(f"    Hidden Param: {param} -> [OK] Allowed for current user")
            else:
                print(f"    Hidden Param: {param} -> [OK] Mutated request failed or no response")

    def run(self, identifiers, auto_numeric_range=None):
        for i in identifiers:
            if i['location'] == 'path' and i['type'] == 'numeric':
                if auto_numeric_range:
                    self.test_numeric_path(i['url'], i['sample'], test_range=auto_numeric_range)
                else:
                    self.test_numeric_path(i['url'], i['sample'])
            elif i['location'] == 'query':
                self.test_query_param(i['url'], i['param'], i['sample'])
            elif i['location'] == 'hidden':
                self.test_hidden_fields(i['url'], i['param'], i['sample'])
        return self.findings

# ----------------------------- Privilege Tester -------------------------------
class PrivilegeTester:
    COMMON_ADMIN = ['/admin','/admin/dashboard','/manage','/manage/users','/administrator']
    def __init__(self, session, logger=None):
        self.session = session
        self.logger = logger or Logger()
        self.findings = []
        self.raw_responses = {}

    def check_path(self, u):
        try:
            r = self.session.get(u, timeout=12)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        self.raw_responses[u] = r.text or ''
        if 200 <= getattr(r,'status_code',0) < 400 and re.search(r"admin|dashboard|manage|users", (r.text or '').lower()):
            self.findings.append({'scenario':'vertical','url':u,'marker':'!!','note':'User with role=USER accessed ADMIN page','severity':'high','evidence':short(r.text,400)})

    def header_spoof(self, u):
        headers = {'X-Forwarded-For':'127.0.0.1','X-Original-URL':'/admin'}
        try:
            r = self.session.get(u, headers=headers, timeout=12)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        self.raw_responses[u + "#spoof"] = r.text or ''
        if 200 <= getattr(r,'status_code',0) < 400 and re.search(r"admin|dashboard", (r.text or '').lower()):
            self.findings.append({'scenario':'header_spoof','url':u,'marker':'!!','note':'Access granted with spoofed headers','headers':headers,'severity':'high','evidence':short(r.text,400)})

    def run(self, endpoints):
        for ep in endpoints:
            p = urlparse(ep).path.lower()
            if any(k in p for k in ('/admin','/manage','/administrator')):
                self.check_path(ep)
                self.header_spoof(ep)
        base = endpoints[0] if endpoints else None
        if base:
            base_root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
            for p in self.COMMON_ADMIN:
                self.check_path(urljoin(base_root, p))
        return self.findings

# ----------------------------- Business Logic Tester -------------------------
class BizLogicTester:
    def __init__(self, session, logger=None):
        self.session = session
        self.logger = logger or Logger()
        self.findings = []

    def price_probe(self, url):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return
        price_keys = [k for k in qs.keys() if 'price' in k.lower() or 'amount' in k.lower() or 'total' in k.lower()]
        if not price_keys:
            return
        k = price_keys[0]
        orig_val = qs[k][0]
        try:
            orig = self.session.get(url, timeout=12)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        if orig_val.isdigit():
            probe = str(max(1, int(orig_val) // 10))
        else:
            probe = '1'
        new_qs = qs.copy(); new_qs[k] = [probe]
        new_q = '&'.join([f"{kk}={new_qs[kk][0]}" for kk in new_qs])
        test_url = parsed._replace(query=new_q).geturl()
        try:
            r = self.session.get(test_url, timeout=12)
            time.sleep(DEFAULT_DELAY)
        except Exception:
            return
        if r and r.status_code == 200 and (r.text or '') != (orig.text or ''):
            self.findings.append({'scenario':'biz_price','url':test_url,'marker':'!!','note':'Potential Price Manipulation','severity':'medium','evidence':short(r.text,400)})

    def run(self, endpoints):
        for ep in endpoints:
            self.price_probe(ep)
        return self.findings

# ----------------------------- Reporter --------------------------------------
class Reporter:
    HTML_HEAD = '''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>UWSF Security Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f8f9fa;color:#212529;margin:0;padding:0}
header{background:#343a40;color:#fff;padding:1rem 2rem} .container{padding:2rem}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.1);margin-bottom:1.25rem;padding:1rem}
.mono{font-family:monospace;background:#f1f3f5;padding:.75rem;border-radius:6px;white-space:pre-wrap;overflow-x:auto}
.severity-high{color:#dc3545;font-weight:bold}.severity-medium{color:#ffc107;font-weight:bold}.severity-low{color:#198754;font-weight:bold}
table{width:100%;border-collapse:collapse}th,td{border:1px solid #dee2e6;padding:.5rem;text-align:left}th{background:#e9ecef}
</style></head><body>
<header><h1>UWSF Security Report</h1><p id="meta"></p></header><div class="container">
'''
    HTML_TAIL = '</div></body></html>'

    def __init__(self, metadata, findings, identifiers, endpoints, logs, raw_responses):
        self.metadata = metadata
        self.findings = findings
        self.identifiers = identifiers
        self.endpoints = endpoints
        self.logs = logs
        self.raw_responses = raw_responses

    def to_json(self, path):
        out = {
            "meta": self.metadata,
            "discovery": {
                "endpoints_count": len(self.endpoints),
                "login_candidates": self.metadata.get('login_candidates', []),
                "identifiers": self.identifiers
            },
            "findings": self.findings,
            "summary": self._summary(),
            "logs": self.logs,
            "artifacts": {"raw_responses_count": len(self.raw_responses)}
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        return path

    def _summary(self):
        s = defaultdict(int)
        for f in self.findings:
            s[f.get('severity','medium')] += 1
        return dict(s)

    def to_html(self, path):
        parts = [self.HTML_HEAD]
        meta_line = f"Target: {html.escape(self.metadata.get('target','-'))} | Scan ID: {html.escape(self.metadata.get('scan_id','-'))} | Date: {html.escape(self.metadata.get('timestamp','-'))}"
        parts.append(f"<script>document.getElementById('meta').innerText = `{meta_line}`</script>")
        # Executive
        parts.append('<div class="card"><h2>Executive Summary</h2>')
        parts.append(f"<p><b>Total Endpoints:</b> {len(self.endpoints)}</p>")
        sev = self._summary()
        parts.append(f"<p><b>Findings by Severity:</b> High ({sev.get('high',0)}), Medium ({sev.get('medium',0)}), Low ({sev.get('low',0)})</p></div>")
        # Auth
        auth = self.metadata.get('authentication', {})
        parts.append('<div class="card"><h2>Authentication & Discovery</h2>')
        parts.append(f"<p><b>Login Used:</b> {html.escape(auth.get('login_used','-'))}</p>")
        parts.append(f"<p><b>Login Success:</b> {html.escape(str(auth.get('login_success',False)))}</p></div>")
        # Identifiers
        parts.append('<div class="card"><h2>Identifiers Found</h2>')
        if self.identifiers:
            parts.append('<table><tr><th>Location</th><th>URL</th><th>Param</th><th>Sample</th><th>Type</th></tr>')
            for it in self.identifiers:
                parts.append('<tr>')
                parts.append(f"<td>{html.escape(it.get('location',''))}</td>")
                parts.append(f"<td>{html.escape(it.get('url',''))}</td>")
                parts.append(f"<td>{html.escape(str(it.get('param','')))}</td>")
                parts.append(f"<td>{html.escape(str(it.get('sample','')))}</td>")
                parts.append(f"<td>{html.escape(it.get('type',''))}</td>")
                parts.append('</tr>')
            parts.append('</table>')
        else:
            parts.append('<p>No identifiers detected.</p>')
        parts.append('</div>')
        # Findings
        parts.append('<div class="card"><h2>Findings</h2>')
        if self.findings:
            for i, f in enumerate(self.findings):
                parts.append(f"<h3>F-{i+1:03} - {html.escape(f.get('note', f.get('title', f.get('url',''))))}</h3>")
                parts.append(f"<p><b>Severity:</b> <span class='severity-{f.get('severity','medium')}'>{html.escape(f.get('severity',''))}</span></p>")
                parts.append(f"<div class='mono'>{html.escape(f.get('url',''))}</div>")
                if f.get('evidence'):
                    parts.append('<details><summary>Evidence (raw)</summary>')
                    parts.append(f"<div class='mono'>{html.escape(str(f.get('evidence','')))}</div></details>")
        else:
            parts.append('<p>No findings detected.</p>')
        parts.append('</div>')
        # Logs
        parts.append('<div class="card"><h2>Execution Logs</h2><div class="mono">')
        for l in self.logs:
            parts.append(html.escape(l) + "\n")
        parts.append('</div></div>')
        parts.append(self.HTML_TAIL)
        content = "\n".join(parts)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

# ----------------------------- Pretty Output (console) ------------------------
def print_idor_priv_summary(findings):
    # Group by scenario
    groups = defaultdict(list)
    for f in findings:
        groups[f.get('scenario','other')].append(f)

    print("\n📌 Contoh Output: IDOR & Privilege Escalation\n")
    # Sequential Path
    print("==========================")
    print("[ IDOR Findings - Sequential Path ]")
    print("==========================")
    seq = groups.get('sequential_path', [])
    if not seq:
        print("None")
    else:
        # sort by URL for consistent output
        for s in sorted(seq, key=lambda x: x.get('url','')):
            marker = "[OK]" if s.get('marker') == 'OK' else "[!!]"
            note = s.get('note')
            print(f"{s.get('url'):<25} -> {marker} {note}")
    print()
    # Sequential Query
    print("==========================")
    print("[ IDOR Findings - Sequential Query ]")
    print("==========================")
    sq = groups.get('sequential_query', [])
    if not sq:
        print("None")
    else:
        for s in sorted(sq, key=lambda x: x.get('url','')):
            marker = "[OK]" if s.get('marker') == 'OK' else "[!!]"
            print(f"{s.get('url'):<25} -> {marker} {s.get('note')}")
    print()
    # Hidden Field
    print("==========================")
    print("[ IDOR Findings - Hidden Field Manipulation ]")
    print("==========================")
    hid = groups.get('hidden_field', [])
    if not hid:
        print("None")
    else:
        # group by form url
        per_form = defaultdict(list)
        for h in hid:
            per_form[h.get('url')].append(h)
        for form_url, items in per_form.items():
            print(f"POST {form_url}")
            for it in items:
                param = it.get('param')
                note = it.get('note')
                print(f"    Hidden Param: {param} -> {note}")
    print()
    # Privilege Escalation - Vertical & Header
    print("==========================")
    print("[ Privilege Escalation - Vertical ]")
    print("==========================")
    vert = groups.get('vertical', []) + groups.get('header_spoof', [])
    if not vert:
        print("None")
    else:
        for v in vert:
            if v.get('scenario') == 'header_spoof':
                print(f"{v.get('url'):<25} -> [!!] {v.get('note')}")
                hdrs = v.get('headers', {})
                for k,val in hdrs.items():
                    print(f"    - {k}: {val}")
            else:
                print(f"{v.get('url'):<25} -> [!!] {v.get('note')}")
    print()

# ----------------------------- Main Flow -------------------------------------
def banner():
    print("""
=====================================
  UWSF - Unified Web Security Framework
  Single-file interactive prototype
=====================================
""")

def legal_confirm():
    print("LEGAL NOTICE: Pastikan Anda memiliki izin eksplisit untuk melakukan security testing pada target ini.")
    print("Jalankan hanya pada lingkungan yang Anda miliki atau yang telah memberikan izin tertulis.")
    ans = input("Saya memiliki izin. Ketik 'Y' untuk melanjutkan: ").strip().upper()
    return ans == 'Y'

def choose_mode():
    print("Pilih mode scan:\n1) Quick (crawl + basic auth detect)\n2) Full (crawl + auth + all tests)\n3) Custom (pilih modul)")
    ch = input('Pilihan (default 2)> ').strip() or '2'
    if ch == '1': return 'quick'
    if ch == '3': return 'custom'
    return 'full'

def prompt_custom_modules():
    print('Pilih modul (pisah koma): 1=IDOR 2=PRIV 3=BIZ')
    s = input('Modules> ').strip()
    sel = set([x.strip() for x in s.split(',') if x.strip()])
    return {'idor': '1' in sel, 'priv': '2' in sel, 'biz': '3' in sel}

def interactive_main():
    banner()
    if not legal_confirm():
        print("Konfirmasi legal tidak diberikan. Exit.")
        return
    target = input("⚡ Target URL (contoh: http://127.0.0.1:5002): ").strip()
    if not target:
        print("Target kosong. Exit.")
        return
    if not urlparse(target).scheme:
        target = "http://" + target
    report_basename = input("Masukkan nama dasar untuk file laporan (contoh: report_website): ").strip() or f"uwsf_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    report_name = sane_filename(report_basename)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    mode = choose_mode()
    custom = None
    if mode == 'custom':
        custom = prompt_custom_modules()

    try:
        delay_in = input(f"Set delay antar-request (detik) [default {DEFAULT_DELAY}]: ").strip()
        delay = float(delay_in) if delay_in else DEFAULT_DELAY
    except Exception:
        delay = DEFAULT_DELAY
    try:
        max_pages_in = input(f"Max pages crawl [default {DEFAULT_MAX_PAGES}]: ").strip()
        max_pages = int(max_pages_in) if max_pages_in else DEFAULT_MAX_PAGES
    except Exception:
        max_pages = DEFAULT_MAX_PAGES

    logger = Logger()
    session = requests.Session()
    crawler = WebCrawler(target, session=session, logger=logger, max_pages=max_pages, delay=delay)

    # initial crawl
    pages = crawler.crawl(depth=DEFAULT_CRAWL_DEPTH)
    endpoints = list(pages.keys())

    # login detection
    ld = LoginDetector(logger=logger)
    candidates = ld.detect(pages)
    print("\n-- Kandidat Login Page (ranked) --")
    for i,c in enumerate(candidates[:10]):
        print(f"[{i}] {c['url']} score={c['score']:.2f} reasons={c['reasons']}")
    chosen_login = None
    if candidates:
        pick = input("Pilih index kandidat atau tekan Enter untuk masukkan manual URL: ").strip()
        if pick.isdigit() and int(pick) < len(candidates):
            chosen_login = candidates[int(pick)]['url']
            chosen_resp = candidates[int(pick)]['response']
        else:
            manu = input("Masukkan manual login URL atau tekan Enter untuk skip: ").strip()
            if manu:
                chosen_login = manu
                try:
                    chosen_resp = requests.get(chosen_login, timeout=10)
                except Exception:
                    chosen_resp = None
    else:
        manu = input("Tidak ditemukan kandidat. Masukkan manual login URL atau tekan Enter untuk skip: ").strip()
        if manu:
            chosen_login = manu
            try:
                chosen_resp = requests.get(chosen_login, timeout=10)
            except Exception:
                chosen_resp = None

    auth_meta = {'login_candidates':[{'url':c['url'],'score':c['score'],'reasons':c['reasons']} for c in candidates],'login_used':None,'login_success':False}
    auth_mgr = AuthManager(session=session, logger=logger)
    credentials = None

    if chosen_login:
        # try to infer method hint
        method_hint = None
        if 'chosen_resp' in locals() and chosen_resp:
            types = ld.extract_auth_types(chosen_resp)
            method_hint = types[0] if types else None
            print(f"Detected authentication candidate types: {types}")
            if method_hint and method_hint != 'unknown':
                print(f"Pilih mode login otomatis: {method_hint}")
        print("\nPilih mode otentikasi: 1) Manual 2) Bruteforce 3) Skip")
        mode_a = input("Pilihan (default 1): ").strip() or '1'
        if mode_a == '1':
            ok, cred, resp = auth_mgr.login_manual(chosen_login, method_hint=method_hint)
            if ok:
                auth_meta['login_used'] = chosen_login
                auth_meta['login_success'] = True
                auth_meta['credentials'] = cred
                credentials = cred
                # after login, optional deeper crawl to discover auth-only pages
                logger.info("[+] Crawling halaman untuk menemukan link/form... (authenticated)")
                pages = crawler.crawl(depth=DEFAULT_CRAWL_DEPTH)
                endpoints = list(pages.keys())
        elif mode_a == '2':
            ok, cred, resp = auth_mgr.login_bruteforce(chosen_login)
            if ok:
                auth_meta['login_used'] = chosen_login
                auth_meta['login_success'] = True
                auth_meta['credentials'] = cred
                credentials = cred
                logger.info("[+] Crawling halaman untuk menemukan link/form... (authenticated)")
                pages = crawler.crawl(depth=DEFAULT_CRAWL_DEPTH)
                endpoints = list(pages.keys())
        else:
            logger.info("User chose to skip authentication.")
    else:
        logger.info("No login URL provided - proceeding unauthenticated where possible.")

    # identifier detection
    idet = IdentifierDetector(logger=logger)
    identifiers = idet.scan_pages(pages)
    logger.info(f"[+] Terdeteksi identifier: {len(identifiers)}")
    if identifiers:
        print("\n[+] Terdeteksi identifier:")
        for it in identifiers:
            if it['location'] == 'path':
                print(f"     path {it['url']} -> None = {it['sample']} ({it['type']})")
            else:
                print(f"     {it['location']} {it['url']} -> {it.get('param')} = {it['sample']} ({it['type']})")

    # ask for auto-generate numeric range if applicable
    numeric_ids = [int(i['sample']) for i in identifiers if i['type']=='numeric' and i['location']=='path' and i['sample'].isdigit()]
    auto_numeric_range = None
    if numeric_ids:
        use_auto = input("\nGunakan auto-generate numeric ID range default 1-5? (y/n): ").strip().lower()
        if use_auto == 'y':
            rng_input = input("Masukkan rentang (contoh 1-5) [default 1-5]: ").strip() or "1-5"
            try:
                a,b = [int(x) for x in rng_input.split('-')][:2]
                auto_numeric_range = list(range(a, b+1))
            except Exception:
                auto_numeric_range = [1,2,3,4,5]
            print(f"[+] Auto-generate numeric IDs: {auto_numeric_range}")

    # choose modules
    run_idor = run_priv = run_biz = False
    if mode == 'quick':
        run_idor = True
    elif mode == 'full':
        run_idor = run_priv = run_biz = True
    elif mode == 'custom' and custom:
        run_idor = custom.get('idor', False)
        run_priv = custom.get('priv', False)
        run_biz = custom.get('biz', False)

    findings = []
    raw_responses = {}

    if run_idor:
        logger.info("[+] Menjalankan IDOR tests")
        idor = IDORTester(session, logger=logger)
        f1 = idor.run(identifiers, auto_numeric_range)
        findings.extend(f1)
        raw_responses.update(idor.raw_responses)

    if run_priv:
        logger.info("[+] Menjalankan Privilege Escalation checks")
        priv = PrivilegeTester(session, logger=logger)
        f2 = priv.run(endpoints)
        findings.extend(f2)
        raw_responses.update(priv.raw_responses)

    if run_biz:
        logger.info("[+] Menjalankan Business Logic & Access Control checks")
        biz = BizLogicTester(session, logger=logger)
        f3 = biz.run(endpoints)
        findings.extend(f3)

    # print summary in requested format
    print_idor_priv_summary(findings)

    # prepare metadata and reports
    scan_id = make_scan_id()
    metadata = {
        "tool": "UWSF",
        "version": "0.1",
        "scan_id": scan_id,
        "target": target,
        "timestamp": now_iso(),
        "login_candidates": [{'url':c['url'],'score':c['score'],'reasons':c['reasons']} for c in candidates],
        "authentication": auth_meta
    }

    # save cookies
    cookies_path = os.path.join(ARTIFACTS_DIR, f"{report_name}_cookies.txt")
    with open(cookies_path, 'w', encoding='utf-8') as f:
        for c in session.cookies:
            f.write(f"{c.name}={c.value}; domain={c.domain}\n")

    # save raw responses artifact
    raw_path = os.path.join(ARTIFACTS_DIR, f"{report_name}_responses.json")
    with open(raw_path, 'w', encoding='utf-8') as f:
        json.dump(raw_responses, f)

    # report
    reporter = Reporter(metadata, findings, identifiers, endpoints, logger.rows, raw_responses)
    json_path = os.path.join(REPORTS_DIR, f"{report_name}.json")
    html_path = os.path.join(REPORTS_DIR, f"{report_name}.html")
    reporter.to_json(json_path)
    reporter.to_html(html_path)

    logger.info("Scan selesai.")
    logger.info(f"Report JSON saved: {json_path}")
    logger.info(f"Report HTML saved: {html_path}")
    logger.info(f"Cookie artifact saved: {cookies_path}")
    logger.info(f"Raw responses saved: {raw_path}")

    print("\nRingkasan:")
    print(f" - Target: {target}")
    print(f" - Scan ID: {scan_id}")
    print(f" - Total findings: {len(findings)}")
    print(f" - Reports: {html_path} and {json_path}")
    print(f" - Artifacts: {cookies_path}, {raw_path}")

if __name__ == '__main__':
    try:
        interactive_main()
    except KeyboardInterrupt:
        print("\nInterrupted by user, exiting.")
