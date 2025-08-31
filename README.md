# WALF 🔒  
**Web Access Logic Framework**  
*Advanced IDOR & Privilege Escalation Testing with HTML Report*

---

## 📌 Deskripsi
**WALF** adalah framework pengujian otomatis yang dirancang untuk mendeteksi kelemahan **akses kontrol** dan **logika bisnis** pada aplikasi web.  
Fokus utama framework ini adalah pada kerentanan:  
- **IDOR (Insecure Direct Object References)**  
- **Privilege Escalation** (horizontal & vertical)  

Tool ini dikembangkan sebagai bagian dari **Final Project Bootcamp Noctra Lupra** dan dapat digunakan untuk:  
✅ Menguji endpoint web secara otomatis  
✅ Membandingkan response antar role user  
✅ Menghasilkan **HTML Report** yang rapi untuk dokumentasi  

---

## ✨ Fitur Utama
- **🔑 Login Multi-Mode**  
  Mendukung login menggunakan `email-password` atau `username-password`.  

- **🕸️ Dynamic Crawling**  
  Mengambil semua endpoint dari `<a href>`, `<form action>`, hingga request dinamis setelah login.  

- **🧪 IDOR Testing Otomatis**  
  - Sequential ID tampering (path & query param)  
  - Hidden field / JSON parameter testing  
  - Horizontal & Vertical privilege escalation  

- **⚡ Session Handling Asli**  
  Menggunakan **cookie & session asli** dari target untuk uji autentikasi.  

- **📑 Reporting**  
  - HTML Report interaktif  
  - Log detail pengujian  

- **🛡️ Exception Handling**  
  Tetap aman dan tidak langsung crash meskipun server mati atau URL salah.  

---
**📖 Catatan**

Tool ini dibuat untuk pembelajaran & research.

Jangan digunakan untuk aktivitas ilegal.

Gunakan hanya di environment legal & authorized.

**🧑‍💻 Kontributor**

Dikembangkan oleh Haykal Rachmady
Sebagai bagian dari tugas akhir Bootcamp Cyber Security – Noctra Lupra
