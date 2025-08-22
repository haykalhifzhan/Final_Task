# Web IDOR Testing Framework 🔒

## Deskripsi Proyek
Framework ini dikembangkan sebagai **tugas akhir** untuk mata kuliah/pelatihan keamanan aplikasi web, dengan fokus pada pengujian **akses kontrol** dan **logika bisnis**, termasuk deteksi **Insecure Direct Object References (IDOR)**.  

Dengan tool ini, kamu bisa secara otomatis:  
- Login ke aplikasi web menggunakan **email/password** atau **username/password**  
- Crawl halaman setelah login untuk menemukan **link, form, dan endpoint API**  
- Menguji endpoint untuk potensi **IDOR** (sequential ID, query param, hidden field, dll)  
- Membandingkan response antar role untuk mendeteksi kemungkinan **privilege escalation**  
- Menampilkan hasil uji dalam bentuk report sederhana  

---

## Fitur Utama
1. **Login Multi-Mode**  
   Bisa login menggunakan `email-password` atau `username-password`.  

2. **Dynamic Crawling**  
   - Mengambil semua `<a href>`, `<form action>` dan `<script src>` setelah login  
   - Mengumpulkan endpoint untuk diuji  

3. **IDOR Testing Otomatis**  
   - Sequential ID tampering (path dan query param)  
   - Hidden field / JSON manipulation  
   - Horizontal & Vertical privilege escalation  

4. **Exception Handling**  
   Aman jika server mati atau URL salah, tidak crash langsung.  

5. **Easy Input**  
   User bisa input target URL, credential, dan path halaman secara manual.  

---

## Persiapan Lab Dummy
Untuk testing, disarankan membuat **server dummy Python (Flask)** dengan multi-role user:  
- User roles: `admin`, `user`, `guest`  
- Endpoint contoh:  
  - `/login` → login page  
  - `/dashboard` → halaman setelah login  
  - `/profile/<id>` → endpoint IDOR  
  - `/orders?id=<id>` → contoh query param IDOR  

