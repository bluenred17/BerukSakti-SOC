# PROGRESS — BerukSakti

Rangkuman status proyek per 3 November 2026: dashboard SOC yang berjalan di VPS sendiri, membaca data asli dari Wazuh, dengan login, RBAC, dan manajemen pengguna.

- Repo: https://github.com/bluenred17/BerukSakti-SOC (branch `master`)
- Dashboard live (butuh login): https://wazuh.toyspedia.fun/soc-automation/
- Halaman pencarian + demo statis: https://beruksakti-soc.vercel.app (dashboard di sana kosong, lihat bagian 6)

---

## 1. Tujuan aplikasi dan requirement utama

BerukSakti terdiri dari dua bagian:

1. **Halaman pencarian BerukSakti** (`google-search.html`): halaman depan pencarian pribadi bergaya Perplexity. Pengguna memilih mencari di web (diteruskan ke Google) atau bertanya ke AI (diteruskan ke claude.ai). Statis, di-host di Vercel.
2. **Dashboard Beruk Sakti Monitoring** (`soc-monitoring.html` + backend `server/app.py`): dashboard Security Operations Center yang **hanya menampilkan data asli dari Wazuh** (tanpa data contoh dan tanpa dataset publik), dijalankan di VPS di belakang login.

Requirement yang sudah diminta dan dipenuhi:

- Sidebar kiri dengan 8 modul: SOC Overview, Alert Management, AI Investigation, Threat Intelligence, Incident Management, Automation Center, SIEM Health, Administration.
- Chatbox Asisten SOC di sisi kanan (aturan kata kunci, menjawab dari data Wazuh).
- Data hanya dari Wazuh. Bagian yang tidak punya sumber di Wazuh tampil kosong dengan keterangan, bukan angka contoh.
- Wajib login dengan akun per orang; peran dan izin (RBAC) ditegakkan server; **halaman Administration hanya untuk administrator**; administrator bisa menambah, menghapus, dan menonaktifkan/mengaktifkan akun.
- Semua waktu ditampilkan dalam **UTC+7 (WIB)**.
- Peta latar dengan busur dari IP sumber asli (GeoIP Wazuh).
- Berfungsi di desktop dan HP.

Rancangan awal yang menjadi acuan: `multi-agent-orchestration-report.md` (SOC Automation dengan FP Classifier, belum dibangun) dan `docs/superpowers/specs/2026-11-03-wazuh-lab-backend-design.md` (desain backend Node.js + SQLite; **tidak diikuti**, lihat keputusan 5).

---

## 2. Tech stack dan struktur folder

**Tech stack**

- **Frontend:** HTML, CSS, dan JavaScript murni dalam satu file (modul ES, memakai top-level `await`), tanpa framework, tanpa build, tanpa library eksternal. Grafik SVG buatan sendiri; peta latar Canvas 2D.
- **Backend:** Python 3.12 standar (`http.server`, `sqlite3`, `hashlib.scrypt`), satu file `server/app.py`, tanpa dependency pip. Berjalan sebagai layanan systemd `soc-automation-dashboard` (user `socauto`, sandbox `ProtectSystem=strict`, `MemoryMax=192M`).
- **SIEM:** Wazuh 4.14.9 (manager, indexer, dashboard) di VPS yang sama. Backend membaca Wazuh Indexer (loopback `127.0.0.1:9200`) dengan akun hanya-baca.
- **Reverse proxy:** Caddy (HTTPS otomatis) di `wazuh.toyspedia.fun`; `/soc-automation/*` diteruskan ke `127.0.0.1:8081` (prefix dibuang oleh `handle_path`).
- **VPS:** Ubuntu 24.04, 2 vCPU, 7,4 GB RAM; firewall hanya 22, 80, 443 (agen Wazuh 1514/1515 hanya dari server web).
- **Hosting statis:** Vercel (auto-deploy tiap `git push` ke `master`) untuk halaman pencarian.

**Struktur repo**

```
D:\Project\aibuilder\
├── google-search.html            # Halaman pencarian (gaya Perplexity)
├── soc-monitoring.html           # Dashboard (frontend, dipasang di VPS sebagai index.html)
├── server/
│   ├── app.py                    # Backend: login, sesi, RBAC, API Wazuh (read-only)
│   ├── login.html                # Halaman login
│   └── manage_users.py           # CLI kelola akun (dijalankan dengan sudo di VPS)
├── vercel.json                   # cleanUrls + rewrite "/" ke halaman pencarian
├── docs/superpowers/specs/       # Desain awal lab Wazuh (sebagian usang)
├── multi-agent-orchestration-report.md   # Rancangan SOC Automation (belum di-commit)
├── README.md, PROGRESS.md
└── raw/                          # Sisa dataset lama, tidak dipakai, tidak masuk Git
```

**Di VPS** (`/opt/soc-automation-dashboard/`, pemilik `root:socauto`): `app.py`, `login.html`, `index.html` (= `soc-monitoring.html`), `manage_users.py`, serta cadangan `*.bak-20261103-*`. Data akun: `/var/lib/soc-automation-dashboard/users.json` (milik `socauto`, mode 600). Database audit/triage: `/var/lib/soc-automation-dashboard/ops.sqlite3`. Konfigurasi: `/etc/soc-automation/dashboard.env`.

---

## 3. Daftar file yang sudah dibuat

| File | Isi | Ukuran |
|---|---|---|
| `soc-monitoring.html` | Dashboard 8 modul + Asisten SOC + peta latar; memuat data dari `api/*` | ±2.510 baris |
| `server/app.py` | Backend: login/sesi, RBAC, kelola pengguna, endpoint Wazuh | ±610 baris |
| `server/login.html` | Form login bertema gelap | 66 baris |
| `server/manage_users.py` | `add / passwd / role / disable / enable / del / list`; kata sandi lewat prompt | ±135 baris |
| `google-search.html` | Halaman pencarian bergaya Perplexity | 378 baris |
| `vercel.json` | `cleanUrls: true`, rewrite `/` → `/google-search` | 6 baris |
| `docs/.../wazuh-lab-backend-design.md` | Desain backend lab Wazuh (Node.js); dipakai sebagai gagasan, tidak diimplementasikan persis | 195 baris |

**Endpoint backend** (semua di bawah `/soc-automation/`, relatif; semuanya butuh login kecuali `healthz`/`api/login`):

| Endpoint | Izin | Isi |
|---|---|---|
| `GET /` | — | Dashboard bila login, form login bila belum |
| `POST api/login`, `api/logout`, `GET api/me` | — | Sesi |
| `GET api/overview` | view | Metrik 24 jam, tren 14 hari (hari WIB), severity, taktik MITRE, ancaman, rule level tinggi, status active response |
| `GET api/alerts` | view | Alert terbaru (maks. 500) + status triage lokal |
| `GET api/health` | view | Cluster, layanan systemd, agen, EPS, peringatan pipeline |
| `GET api/geo` | view | IP sumber + koordinat (GeoIP Wazuh) |
| `GET api/ioc`, `api/ioc-lists` | view | Lookup indikator, daftar IOC bawaan Wazuh, alert rule IOC |
| `GET api/investigate`, `api/cases[/id]` | view | Korelasi heuristik; kasus lokal |
| `GET api/audit` | audit | Audit log (100 terakhir) |
| `GET api/admin` | users | Info koneksi, daftar pengguna, matriks RBAC |
| `POST api/users/{add,delete,disable,enable}` | users | Kelola akun |
| `POST api/triage`, `api/cases*` | triage / cases | Ada di backend, belum dipakai UI |

**Riwayat commit penting**

| Commit | Isi |
|---|---|
| `d9b0f3d`–`25b7672` | Dashboard 8 modul, halaman pencarian, Vercel, PROGRESS awal |
| `e7577f9` | Chatbox Asisten SOC (simulasi) |
| `c43ee6f`, `a640c13`, `8b9962f` | Dataset publik EuRepoC, UNSW-NB15, CISA KEV (kemudian dihapus) |
| `24262c0` | Dashboard dihubungkan ke Wazuh live di VPS |
| `720a098` | Hanya data Wazuh; data contoh, dataset publik, dan peta acak dihapus |
| `a9c9a82` | Login aplikasi dengan akun per orang |
| `7646e7b` | RBAC enam peran + waktu WIB |
| `6675fae` | Peta latar dengan busur dari GeoIP Wazuh |
| `9113ef1` | Daftar IOC Wazuh + kelola pengguna dari dashboard |
| `b1bc7a6` | Administration hanya untuk administrator; audit log ke Incident Management |

---

## 4. Fitur yang sudah selesai dan sudah diuji

Pengujian: tiap perubahan backend diuji di **instance terpisah di VPS** (port 8091, sandbox systemd yang sama dengan produksi, akun uji acak yang dihapus sesudahnya) memakai skrip `curl` per peran, lalu dicek di browser lewat tunnel SSH; setelah itu di-deploy dengan cadangan dan rollback otomatis. Tidak ada test otomatis di repo.

- [x] **Login dan sesi**: hash scrypt; cookie `HttpOnly`, `SameSite=Lax`, `Secure` di belakang HTTPS; sesi habis setelah 2 jam tidak aktif atau 12 jam total; batas 5 percobaan gagal per 15 menit (per IP dan per nama); cek `Origin` pada semua POST; CSP dan `Cache-Control: no-store`; akun/peran dibaca ulang di setiap permintaan. Diuji: 19 skenario login.
- [x] **RBAC enam peran** (Administrator, SOC Manager, Analyst T3/T2/T1, Read-only; matriks di halaman Administration, ditegakkan server). Diuji per peran: triage, kasus, daftar pengguna, audit.
- [x] **Kelola pengguna** (admin): tambah, hapus, nonaktifkan/aktifkan; sesi dicabut seketika; tidak bisa menghapus/menonaktifkan diri sendiri; minimal satu admin aktif; tercatat di audit log. Diuji 19 skenario.
- [x] **Administration hanya untuk administrator**: `api/admin` 403 untuk peran lain, menu dan rute disembunyikan.
- [x] **SOC Overview**: alert 24 jam, tren harian, severity, taktik MITRE, ancaman teratas, rule level tinggi, agen aktif.
- [x] **Alert Management**: 500 alert terbaru dari 7 hari (hanya baca), filter, status triage lokal.
- [x] **AI Investigation**: korelasi heuristik per alert (skor risiko dari level rule, alert terkait 24 jam, tag MITRE). Bukan LLM.
- [x] **Threat Intelligence**: lookup IOC terhadap daftar bawaan Wazuh (199 IP, 200 domain, 199 hash) dan kemunculannya di log; IP sumber teratas; alert rule IOC.
- [x] **Incident Management**: tabel kasus lokal dan timeline (saat ini kosong); kartu audit log.
- [x] **Automation Center**: status active response Wazuh (saat ini tidak ada).
- [x] **SIEM Health**: cluster, layanan, agen, EPS, peringatan pipeline.
- [x] **Administration**: koneksi, pengguna, RBAC, integrasi.
- [x] **Peta latar**: titik benua + busur animasi dari IP sumber asli 24 jam (52 IP, 22 negara saat diuji), warna menurut severity.
- [x] **Asisten SOC**: aturan kata kunci, menjawab dari data Wazuh, bisa mencari IP/hash ke Wazuh.
- [x] **Waktu WIB** di seluruh tampilan, termasuk batas hari pada hitungan harian.
- [x] **Halaman pencarian** (`google-search.html`): mode Cari/Tanya AI, saran riwayat, pencarian suara, responsif.

---

## 5. Fitur yang belum selesai

- [ ] **Ubah peran akun dan reset kata sandi dari dashboard** (sekarang lewat `manage_users.py role` / `passwd`); ganti kata sandi sendiri; MFA.
- [ ] **Triage dan kasus dari UI**: backend `POST api/triage` dan `api/cases*` sudah ada, tapi antarmuka masih hanya baca (belum dihubungkan agar tidak menulis ke database tanpa uji UI).
- [ ] **Playbook, persetujuan aksi, dan riwayat eksekusi** (izin sudah ada di matriks, ditandai "belum ada fiturnya"); tidak ada sumber data di Wazuh. Butuh SOAR atau skrip active response.
- [ ] **Integrasi eksternal** (VirusTotal, MISP, OTX) dan feed IOC otomatis. Wazuh belum punya integrasi apa pun (`<integration>` = 0); daftar IOC bawaan statis. Mengubahnya butuh perubahan konfigurasi Wazuh dan restart manager.
- [ ] **Incident dari data asli** dan **FP Classifier / LLM** (roadmap di `multi-agent-orchestration-report.md`); Fase 0 (analisis FP 30–90 hari) belum dikerjakan.
- [ ] **Metrik MTTD/MTTR/FP rate**: tidak ada sumber di Wazuh, jadi tidak ditampilkan.
- [ ] **Refresh otomatis**: data dimuat saat halaman dibuka; perlu muat ulang untuk memperbarui.
- [ ] **Metrik CPU/heap/disk per node** belum tersedia dari API.
- [ ] **Tampilan alert lebih dari 500** (pagination) dan filter rentang waktu.
- [ ] **Asisten SOC dengan model AI sungguhan** (`askAssistant()` siap diganti).
- [ ] **Keputusan Vercel**: nonaktifkan, atau ubah jadi halaman pengarah ke dashboard.
- [ ] **Halaman pencarian**: menu Pustaka dan link footer belum punya tujuan.

---

## 6. Bug atau kendala yang sedang terjadi

| Kendala | Dampak | Status |
|---|---|---|
| **Vercel menampilkan dashboard kosong** dengan peringatan "Tidak bisa terhubung ke Wazuh". | Tidak ada API di Vercel; tidak ada data bocor. Halaman pencarian tetap normal. | Menunggu keputusan |
| **Sesi disimpan di memori**: restart layanan mengeluarkan semua pengguna. | Setiap deploy memaksa login ulang. | Diterima; bisa dipindah ke SQLite |
| `/etc/soc-automation/caddy-auth.txt` berisi kata sandi basic auth lama yang tak terpakai; `/etc/caddy/Caddyfile.bak-20261103` berisi hash lamanya. | Rahasia menganggur di server. | Menunggu persetujuan hapus |
| `/etc/soc-automation/users.json.dipindah-20261103` adalah salinan lama berkas akun (tidak dipakai). | Bisa membingungkan. | Hapus bila sudah yakin |
| **Tujuan busur peta dipatok ke Jakarta** (`MAP_TARGET` di `soc-monitoring.html`); IP sendiri (mis. IP login SSH) ikut tergambar. | Tampilan, bukan data. | Bisa disesuaikan |
| Daftar IOC bawaan kecil dan statis. | "Tidak ada di daftar" belum berarti aman. | Ditulis jelas di UI |
| **Zona waktu server Wazuh +08:00**, tampilan +07:00. | Waktu log mentah di server berbeda 1 jam dari tampilan; dashboard sudah mengonversi. | Sudah ditangani |
| Peringatan pipeline asli di SIEM Health: `indexer-connector ... wazuh-states-inventory-*` gagal diinisialisasi. | Indeks inventaris Wazuh belum terbentuk; perlu diselidiki sisi Wazuh. | Belum diselidiki |
| Tidak ada test otomatis; pengujian lewat skrip sementara. | Regresi baru ketahuan saat diuji ulang manual. | Belum diperbaiki |
| Peringatan Git `LF will be replaced by CRLF`. | Tidak berdampak. | Dibiarkan |
| Akun Vercel belum memakai 2FA. | Risiko keamanan akun. | Keputusan pemilik akun |

---

## 7. Keputusan teknis penting

1. **Satu file per halaman, tanpa framework dan tanpa build**; grafik SVG buatan sendiri.
2. **Dashboard hanya memakai data Wazuh.** Data contoh, dataset publik (UNSW-NB15, EuRepoC, CISA KEV), dan peta serangan acak dihapus agar tidak ada angka palsu di samping data asli. Bagian tanpa sumber tampil kosong dengan penjelasan. Riwayat kodenya ada di git.
3. **Backend dan dashboard di VPS yang sama dengan Wazuh**, satu origin: cookie sesi sederhana, kredensial Wazuh dan port indexer tidak keluar dari VPS. Akses ke Wazuh hanya-baca (akun `kibanaserver`).
4. **URL di frontend selalu relatif** (`api/...`) karena Caddy `handle_path` membuang prefix `/soc-automation`; URL absolut akan jatuh ke Wazuh Dashboard.
5. **Memakai backend Python yang sudah ada di VPS**, bukan Node.js + SQLite seperti desain awal di `docs/`: nol dependency, sudah terpasang sebagai layanan, cukup diperluas.
6. **Wazuh tidak diubah.** GeoIP ternyata sudah aktif di pipeline Filebeat (field `GeoLocation` terisi di indexer); daftar IOC dan konfigurasi dibaca saja. Perubahan konfigurasi Wazuh (restart manager) hanya dengan persetujuan eksplisit.
7. **Izin ditegakkan di server per endpoint**, bukan hanya disembunyikan di UI. Definisi peran (`ROLE_DEFS`) satu sumber di `app.py` dan dikirim ke UI. Nama lama `viewer` dan `analyst` dipetakan ke `readonly` dan `analyst_t2`.
8. **Berkas akun di `/var/lib/soc-automation-dashboard/`**, karena sandbox `ProtectSystem=strict` membuat `/etc` hanya-baca bagi layanan; ini memungkinkan admin mengelola akun dari dashboard.
9. **Kata sandi tidak pernah lewat chat atau argumen shell**: `manage_users.py` memakai `getpass`; form dashboard mengirim lewat HTTPS; yang disimpan hanya hash scrypt.
10. **Audit log pindah ke Incident Management** supaya izin "Lihat audit log" milik Manager dan Read-only tetap bermakna setelah Administration dijadikan khusus admin.
11. **Semua waktu WIB (UTC+7)** lewat `Asia/Jakarta` di browser; batas hari pada agregasi memakai `time_zone: +07:00` di Wazuh Indexer.
12. **Pengujian di instance terpisah dengan sandbox yang sama**, akun uji acak, lalu dihapus; deploy dengan cadangan `*.bak-*`, pemeriksaan otomatis, dan rollback bila gagal. Layanan produksi tidak dipakai untuk uji.
13. **Hasil "AI Investigation" diberi label heuristik** (aturan, bukan model) supaya tidak menyesatkan; teks dari data selalu dimasukkan dengan `textContent`.
14. **Proyek non-komersial**; Vercel tetap dipakai untuk halaman pencarian lewat integrasi GitHub.

---

## 8. Task berikutnya yang harus dikerjakan

Urutan yang disarankan:

1. **Bersihkan sisa di VPS** (dengan persetujuan): hapus `caddy-auth.txt`, `Caddyfile.bak-20261103`, dan `users.json.dipindah-20261103`; pastikan tidak ada cadangan lain yang berisi rahasia.
2. **Putuskan nasib Vercel**: nonaktifkan project dashboard, atau ganti dengan halaman pengarah ke `wazuh.toyspedia.fun/soc-automation/`.
3. **Selidiki peringatan `indexer-connector`** di SIEM Health (indeks `wazuh-states-inventory-*`).
4. **Tombol ubah peran dan reset kata sandi** di halaman Administration; ganti kata sandi sendiri; pertimbangkan MFA (TOTP).
5. **Hubungkan triage dan kasus ke UI** (backend sudah ada), dengan audit log per aksi.
6. **Refresh otomatis** (polling) dan pagination alert; pindahkan sesi ke SQLite agar restart tidak mengeluarkan pengguna.
7. **Feed IOC otomatis** ke Wazuh (daftar CDB dari abuse.ch/OTX lewat skrip terjadwal) dan integrasi VirusTotal; perlu restart manager, jadi dijadwalkan dan disetujui dulu.
8. **Fase 0 laporan orkestrasi**: ekspor alert 30–90 hari dari Wazuh, hitung rule paling berisik dan estimasi FP, lalu bangun FP Classifier dengan aturan keputusan dan fail-safe, tag ditulis kembali dengan persetujuan manusia.
9. **Asisten SOC dengan model sungguhan** setelah login ada (sudah): `askAssistant()` memanggil endpoint backend, API key hanya di server.
10. **Test otomatis** untuk backend (login, RBAC, kelola pengguna) menggantikan skrip sementara; pertimbangkan memecah `soc-monitoring.html` menjadi file terpisah.
11. **Opsional**: commit `multi-agent-orchestration-report.md`; perbarui atau hapus `docs/.../wazuh-lab-backend-design.md`; atur ulang `MAP_TARGET` dan kecualikan IP sendiri dari peta; aktifkan 2FA akun Vercel.
