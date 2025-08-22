import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from difflib import SequenceMatcher

ID_RANGE = range(1, 6)

def login(session, base_url, mode, user, password):
    login_url = f"{base_url}/login"
    payload = {"email": user, "password": password} if mode=="email" else {"username": user, "password": password}
    try:
        r = session.post(login_url, data=payload, timeout=5)
        if r.ok and ("Logout" in r.text or "Dashboard" in r.text):
            print(f"[+] Login berhasil sebagai {user}")
            return True
        else:
            print("[-] Login gagal, periksa credential")
            return False
    except Exception as e:
        print(f"[-] Error login: {e}")
        return False

def crawl_links(session, base_url, start_path="/dashboard"):
    """Crawl halaman awal untuk semua link & form"""
    target_url = urljoin(base_url, start_path)
    try:
        r = session.get(target_url, timeout=5)
    except Exception as e:
        print(f"[-] Gagal akses {target_url}: {e}")
        return []

    soup = BeautifulSoup(r.text, "html.parser")
    links = [urljoin(base_url, a.get("href")) for a in soup.find_all("a", href=True)]
    forms = [urljoin(base_url, f.get("action")) for f in soup.find_all("form", action=True)]
    return list(set(links + forms))

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def test_sequential_path(session, url):
    for i in ID_RANGE:
        test_url = url.replace("{id}", str(i))
        try:
            r = session.get(test_url, timeout=5)
            line = f"GET {test_url} -> {r.status_code} ({len(r.text)} bytes)"
            if r.status_code == 200 and i != 1:
                line += " [!!! VULNERABLE !!!]"
            print(line)
        except:
            pass

def test_query_param(session, url):
    """Ganti param yang ada dengan range ID_RANGE"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for key in qs.keys():
        for i in ID_RANGE:
            qs[key] = [str(i)]
            new_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
            try:
                r = session.get(new_url, timeout=5)
                line = f"GET {new_url} -> {r.status_code}"
                if r.status_code == 200 and i != 1:
                    line += " [!!! VULNERABLE !!!]"
                print(line)
            except:
                pass

def test_hidden_field(session, url):
    """Submit dummy hidden field POST untuk test IDOR"""
    try:
        data = {"user_id": 1, "name": "HACKED"}
        r = session.post(url, data=data, timeout=5)
        line = f"POST {url} user_id=1 -> {r.status_code}"
        if r.status_code == 200:
            line += " [!!! VULNERABLE !!!]"
        print(line)
    except:
        pass

def test_vertical_privilege(session, base_url):
    url = f"{base_url}/admin"
    try:
        r = session.get(url, timeout=5)
        line = f"GET /admin -> {r.status_code}"
        if r.status_code == 200:
            line += " [!!! VULNERABLE - Akses Admin Diberikan! !!!]"
        print(line)
    except:
        pass

def test_horizontal_privilege(session, base_url):
    for i in ID_RANGE:
        url = f"{base_url}/profile/{i}"
        try:
            r = session.get(url, timeout=5)
            line = f"GET {url} -> {r.status_code} ({len(r.text)} bytes)"
            if r.status_code == 200 and i != 1:
                line += " [!!! VULNERABLE !!!]"
            print(line)
        except:
            pass

if __name__ == "__main__":
    base_url = input("Target URL (contoh: http://127.0.0.1:5002): ").strip()
    print("Pilih mode login: 1. Email  2. Username")
    choice = input("Masukkan pilihan (1/2): ").strip()
    mode = "email" if choice=="1" else "username"
    user = input(f"Masukkan {mode}: ").strip()
    password = input("Masukkan password: ").strip()

    session = requests.Session()
    if login(session, base_url, mode, user, password):
        print("\n[+] Crawling halaman untuk menemukan link/form...")
        targets = crawl_links(session, base_url)
        for t in targets:
            print("   ", t)

        print("\n[+] Mulai IDOR testing...")
        for t in targets:
            if "{id}" in t:  # Path IDOR test
                test_sequential_path(session, t)
            elif "?" in t:    # Query param IDOR test
                test_query_param(session, t)
            else:            # POST hidden field
                test_hidden_field(session, t)

        test_vertical_privilege(session, base_url)
        test_horizontal_privilege(session, base_url)
    else:
        print("[-] Login gagal, tidak bisa lanjut IDOR testing.")
