# PROGRESS — BerukSakti

Rangkuman status proyek per 3 November 2026 (commit terakhir `b116fd0`).

- Repo: https://github.com/bluenred17/BerukSakti-SOC (branch `master`)
- Website: https://beruksakti-soc.vercel.app

---

## 1. Tujuan aplikasi dan requirement utama

BerukSakti terdiri dari dua halaman web statis:

1. **Halaman pencarian BerukSakti** (`google-search.html`): halaman depan pencarian pribadi bergaya Perplexity. Pengguna bisa memilih mencari di web (diteruskan ke Google) atau bertanya ke AI (diteruskan ke claude.ai).
2. **Dashboard Beruk Sakti Monitoring** (`soc-monitoring.html`): dashboard Security Operations Center (SOC) untuk memantau alert, insiden, intelijen ancaman, otomasi, dan kesehatan SIEM.

Requirement utama yang diminta:

- Halaman pencarian bergaya Perplexity: sidebar ikon, kotak tanya besar, mode **Cari** / **Tanya AI**.
- Dashboard dengan sidebar kiri berisi 8 modul:

| No | Modul | Fitur utama yang diminta |
|---|---|---|
| 1 | SOC Overview | Security KPI, alert trends, severity distribution, top threats |
| 2 | Alert Management | Alert queue, filtering, severity, assignment, triage status |
| 3 | AI Investigation | AI alert analysis, log correlation, incident summary, risk scoring |
| 4 | Threat Intelligence | IOC lookup, IP/domain/hash reputation, enrichment |
| 5 | Incident Management | Incident tracking, case management, investigation timeline |
| 6 | Automation Center | Automated playbooks, workflow execution, approval management |
| 7 | SIEM Health | Cluster health, ingestion monitoring, agent status, pipeline errors |
| 8 | Administration | User management, RBAC, integration settings, audit |

- Bisa dibuka publik oleh siapa pun lewat website.
- Tampilan berfungsi di desktop dan HP.

---

## 2. Tech stack dan struktur folder

**Tech stack**

- HTML, CSS, dan JavaScript murni (vanilla), tanpa framework, tanpa build step, tanpa library eksternal.
- Grafik digambar sendiri dengan SVG; peta ancaman di latar belakang dashboard memakai Canvas 2D.
- Data contoh disimpan sebagai objek `DATA` di dalam `soc-monitoring.html`.
- Git + GitHub untuk versi kode.
- Vercel untuk hosting statis, deploy otomatis setiap `git push` ke `master`.

**Struktur folder**

```
D:\Project\aibuilder\
├── .git/
├── README.md              # Penjelasan proyek (perlu diperbarui, lihat bagian 6)
├── PROGRESS.md            # File ini
├── google-search.html     # Halaman pencarian BerukSakti (gaya Perplexity)
├── soc-monitoring.html    # Dashboard Beruk Sakti Monitoring, 8 modul
└── vercel.json            # Konfigurasi Vercel: cleanUrls + rewrite "/" ke halaman pencarian
```

Setiap halaman berdiri sendiri dalam satu file (HTML, CSS, dan JS jadi satu).

---

## 3. Daftar file yang sudah dibuat

| File | Isi | Ukuran |
|---|---|---|
| `google-search.html` | Halaman pencarian BerukSakti bergaya Perplexity | ±380 baris |
| `soc-monitoring.html` | Dashboard SOC 8 modul + data contoh + peta ancaman animasi | ±2.330 baris |
| `vercel.json` | `cleanUrls: true`, rewrite `/` → `/google-search` | 6 baris |
| `README.md` | Penjelasan proyek (masih versi lama) | — |
| `PROGRESS.md` | Rangkuman progres ini | — |

**Riwayat commit**

| Commit | Isi |
|---|---|
| `d9b0f3d` | Commit awal: dashboard Beruk Sakti Monitoring dan file proyek |
| `71dcaf2` | Ubah tampilan `google-search.html` menjadi bergaya Perplexity |
| `15193d4` | Tambah `vercel.json` agar halaman utama membuka `google-search.html` |
| `b35973d` | Perbaiki rewrite Vercel: tujuan tanpa `.html` karena `cleanUrls` aktif |
| `51c4c65` | Tambah sidebar panel di dashboard |
| `b116fd0` | Kembangkan dashboard menjadi 8 modul SOC |

**URL publik (sudah dicek mengembalikan HTTP 200)**

| URL | Halaman |
|---|---|
| https://beruksakti-soc.vercel.app/ | Halaman pencarian |
| https://beruksakti-soc.vercel.app/google-search | Halaman pencarian |
| https://beruksakti-soc.vercel.app/soc-monitoring | Dashboard (modul bisa dibuka langsung dengan `#overview`, `#alerts`, `#ai`, `#intel`, `#incidents`, `#automation`, `#siem`, `#admin`) |

---

## 4. Fitur yang sudah selesai dan sudah diuji

Pengujian dilakukan di browser pane aplikasi Claude (ukuran desktop 1280×800 dan HP 375×812), dengan pengecekan console error dan pengujian interaksi lewat JavaScript. Tidak ada test otomatis di repo.

### Halaman pencarian (`google-search.html`)

- [x] Tampilan bergaya Perplexity: sidebar ikon (Beranda, Jelajah, Pustaka), logo serif "beruksakti", kotak tanya yang memanjang otomatis, chip saran cepat.
- [x] Mode **Cari** (ke Google) dan **Tanya AI** (ke claude.ai); mode terakhir diingat di `localStorage`.
- [x] Enter mengirim, Shift+Enter baris baru, `/` fokus ke kotak tanya.
- [x] Saran dari riwayat pencarian dan kata kunci contoh, bisa dipilih dengan panah atas/bawah.
- [x] Pencarian suara (Web Speech API, bahasa Indonesia).
- [x] Responsif di HP (sidebar pindah ke bawah). Diuji: desktop dan HP, tanpa error console.

### Dashboard (`soc-monitoring.html`)

- [x] **Sidebar 8 modul** dengan badge angka yang ikut berubah (alert belum ditugaskan, insiden kritis, persetujuan tertunda, sumber log/agen bermasalah). Di HP berubah jadi menu geser di atas, tanpa scroll horizontal.
- [x] **Navigasi modul** lewat klik dan lewat hash URL (`#alerts`, dst.).
- [x] **1. SOC Overview**: 6 KPI, grafik tren alert 14 hari (tooltip), distribusi severity 7 hari dengan perbandingan minggu sebelumnya, tabel ancaman teratas, grafik taktik MITRE ATT&CK.
- [x] **2. Alert Management**: antrean 14 alert, filter (cari, severity, status, analis), ubah analis dan status triage langsung di tabel. Diuji: penugasan menurunkan badge 5 → 4; filter Critical menampilkan 3 baris.
- [x] **3. AI Investigation**: daftar skor risiko, kartu per insiden (kesimpulan, keyakinan, ringkasan, korelasi log, temuan, rekomendasi).
- [x] **4. Threat Intelligence**: lookup IOC dengan deteksi tipe (IPv4, domain, MD5/SHA-1/SHA-256), hasil reputasi dan enrichment (skor, negara, ASN, tag, insiden terkait), tabel feed, tabel IOC yang bisa diklik. Diuji: IOC dikenal, IP tidak dikenal, dan format salah.
- [x] **5. Incident Management**: tabel kasus dengan SLA (lewat SLA merah), timeline investigasi per kasus (klik baris), tabel insiden yang bisa dicari dan diurutkan. Diuji: klik kasus mengganti timeline.
- [x] **6. Automation Center**: tombol Setujui/Tolak aksi, playbook dengan toggle aktif, riwayat eksekusi. Diuji: menyetujui APR-311 menurunkan badge 3 → 2 dan mengubah status eksekusi menjadi Running.
- [x] **7. SIEM Health**: status cluster (Green/Yellow/Red), CPU/heap/disk tiap node, ingestion per sumber log, status agen, error pipeline.
- [x] **8. Administration**: tabel pengguna (MFA, status), matriks RBAC, integrasi dengan toggle, audit log yang ikut mencatat perubahan di halaman. Diuji: audit log bertambah setelah penugasan dan persetujuan.

### Deploy

- [x] Repo di-push ke GitHub.
- [x] Project Vercel `beruksakti-soc` (team BerukSakti) terhubung ke repo; deploy otomatis saat push ke `master`. Diuji: tiga URL di atas mengembalikan 200, dan versi 8 modul sudah tayang.

---

## 5. Fitur yang belum selesai

- [ ] **Data asli**: semua angka, nama, IOC, dan hasil "AI" adalah data contoh yang ditulis langsung di objek `DATA`. Belum terhubung ke SIEM, EDR, feed intelijen, atau model AI sungguhan.
- [ ] **Penyimpanan perubahan**: penugasan alert, status triage, persetujuan aksi, toggle playbook/integrasi, dan audit log hanya tersimpan di memori. Hilang saat halaman di-refresh.
- [ ] **Login dan hak akses**: dashboard terbuka untuk siapa pun. RBAC dan manajemen pengguna baru berupa tampilan, belum membatasi akses.
- [ ] **Aksi nyata**: tombol Setujui, toggle integrasi, dan lookup IOC tidak memanggil sistem luar mana pun.
- [ ] **Data "live"**: tidak ada refresh otomatis; waktu dan angka tetap per 2 November 2026.
- [ ] **Halaman pencarian**: menu Pustaka dan link di footer (Tentang, Privasi, Persyaratan, Bahasa Indonesia) belum punya tujuan.
- [ ] **README.md** belum diperbarui (lihat bagian 6).
- [ ] **GitHub Pages** belum diaktifkan (opsional, karena Vercel sudah dipakai).

---

## 6. Bug atau kendala yang sedang terjadi

| Kendala | Dampak | Status |
|---|---|---|
| `README.md` masih menjelaskan versi lama halaman pencarian (gaya Google, tombol "Saya Lagi Beruntung", "Chat with AI") dan tidak menyebut dashboard maupun Vercel. | Dokumentasi menyesatkan. | Belum diperbaiki |
| Dashboard publik tanpa login. | Aman selama datanya contoh. Tidak boleh diisi data SIEM asli sebelum ada autentikasi. | Kendala desain |
| Di pratinjau `data:` URL (browser pane aplikasi Claude) hash URL tidak bisa berubah. | Navigasi lewat hash tidak jalan di pratinjau. Sudah diatasi: klik sidebar langsung mengganti modul. Di Vercel normal. | Sudah ditangani |
| Grafik di dashboard terlihat terlalu besar sesaat setelah ukuran jendela berubah drastis. | Kosmetik, hilang setelah ±120 ms saat grafik digambar ulang. | Bukan bug, dibiarkan |
| Peringatan Git `LF will be replaced by CRLF` setiap commit. | Tidak berdampak; hanya akhir baris di Windows. | Dibiarkan |
| Branch kerja `master`, sedangkan nama branch utama yang dianjurkan `main`. | Vercel dan GitHub memakai `master` sebagai default, jadi tidak masalah. | Dibiarkan |
| Akun Vercel belum memakai 2FA (tawaran 2FA ditunda dengan "Remind Me Later"). | Risiko keamanan akun. | Keputusan pemilik akun |

---

## 7. Keputusan teknis penting

1. **Satu file per halaman, tanpa framework dan tanpa build.** Bisa dibuka langsung dengan klik dua kali, mudah di-host statis, tidak ada dependency.
2. **Grafik digambar sendiri (SVG/Canvas), bukan library chart.** Menghindari ketergantungan CDN dan menjaga ukuran tetap kecil.
3. **Semua data di satu objek `DATA`** di `soc-monitoring.html`, ditandai "Data contoh (ganti dengan data SIEM Anda)". Saat nanti diganti dengan data asli, cukup objek ini yang diubah atau diisi dari API.
4. **Satu halaman, banyak modul** (`<section class="soc-view">` yang disembunyikan/ditampilkan), dengan routing lewat hash URL dan klik sidebar. Tidak perlu server-side routing.
5. **Grafik hanya digambar saat modulnya terlihat**, karena ukurannya diukur dari kotak di layar (kotak tersembunyi berukuran 0).
6. **Teks dari data selalu dimasukkan dengan `textContent`**, bukan `innerHTML`, supaya aman dari injeksi HTML ketika nanti diisi data asli.
7. **Mode gelap saja** untuk dashboard (gaya ruang SOC); warna status konsisten: hijau = sehat, kuning = perlu perhatian, merah = bermasalah, biru = sedang berjalan.
8. **Vercel dengan `cleanUrls`**: alamat tanpa `.html`; tujuan rewrite juga harus ditulis tanpa `.html` (penyebab 404 pada deploy pertama).
9. **Hosting di Vercel lewat integrasi GitHub**, bukan Vercel CLI: setiap `git push` ke `master` otomatis deploy.
10. **Perubahan di halaman sengaja tidak disimpan** (tanpa `localStorage`) karena ini data contoh bersama; penyimpanan sungguhan butuh backend.

---

## 8. Task berikutnya yang harus dikerjakan

Urutan yang disarankan:

1. **Perbarui `README.md`**: jelaskan kedua halaman, URL Vercel, cara deploy, dan bahwa data dashboard adalah contoh.
2. **Tentukan sumber data asli** (misalnya Elastic SIEM, EDR, feed TI) dan rancang backend/API kecil (mis. Vercel Serverless Functions) yang menyediakan data dalam bentuk yang sama dengan objek `DATA`.
3. **Tambahkan autentikasi** sebelum data asli masuk (mis. Vercel Password Protection, SSO, atau login sendiri), lalu terapkan RBAC yang sudah ada di modul Administration.
4. **Simpan perubahan pengguna** (penugasan, status triage, persetujuan, toggle, audit log) ke database lewat backend.
5. **Sambungkan aksi nyata**: lookup IOC ke API reputasi, persetujuan ke mesin SOAR/playbook, toggle integrasi ke konfigurasi asli.
6. **Refresh data otomatis** (polling berkala) dan tampilkan waktu pembaruan terakhir.
7. **Lengkapi halaman pencarian**: tujuan untuk menu Pustaka (mis. riwayat pencarian) dan link footer.
8. **Pertimbangkan memecah `soc-monitoring.html`** (±2.330 baris) menjadi file CSS/JS/data terpisah begitu mulai terhubung ke API.
9. **Opsional**: aktifkan 2FA di akun Vercel; ganti nama branch ke `main` bila diinginkan.
