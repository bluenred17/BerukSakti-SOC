# BerukSakti

BerukSakti terdiri dari dua bagian:

- **Halaman pencarian** (`google-search.html`): halaman depan pencarian pribadi bergaya Perplexity.
- **Beruk Sakti Monitoring** (`soc-monitoring.html` + `server/`): dashboard SOC yang menampilkan **data asli dari Wazuh**, dijalankan di VPS sendiri di belakang login.

Proyek non-komersial.

| | URL |
|---|---|
| Dashboard (perlu login) | https://wazuh.toyspedia.fun/soc-automation/ |
| Halaman pencarian | https://beruksakti-soc.vercel.app |
| Repo | https://github.com/bluenred17/BerukSakti-SOC |

Status lengkap, keputusan teknis, dan daftar tugas ada di [PROGRESS.md](PROGRESS.md).

## Dashboard

Sembilan modul di sidebar kiri, ditambah Asisten SOC di sisi kanan (aturan kata kunci, bukan model AI) dan peta latar dengan busur dari IP sumber alert (GeoIP Wazuh).

| Modul | Isi |
|---|---|
| SOC Overview | Alert 24 jam, tren harian, severity, taktik MITRE, ancaman dan rule teratas |
| Alert Management | Alert terbaru dari Wazuh (hanya baca), filter, status triage |
| AI Investigation | Skor risiko dan korelasi alert per alert (aturan, bukan LLM) |
| Threat Intelligence | Lookup IOC terhadap daftar IOC bawaan Wazuh, IP sumber teratas |
| Incident Management | Kasus lokal, timeline, audit log |
| Automation Center | Status active response Wazuh |
| SIEM Health | Cluster, layanan, agen, EPS, peringatan pipeline |
| Fail2ban | Jail, IP yang sedang diblokir, riwayat ban/unban, skor AbuseIPDB (hanya baca) |
| Administration | Koneksi, pengguna, matriks RBAC, integrasi (hanya administrator) |

Bagian yang tidak punya sumber di Wazuh (playbook, persetujuan aksi, MTTD/MTTR) tidak ditampilkan atau dikosongkan. Tidak ada data contoh. Semua waktu dalam WIB (UTC+7).

### Login dan peran (RBAC)

Setiap orang punya akun sendiri; izin ditentukan oleh peran dan ditegakkan di server.

| Izin | Admin | Manager | T3 | T2 | T1 | Read-only |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Lihat dashboard | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Triage alert | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| Kelola insiden & kasus | ✓ | ✓ | ✓ | ✓ | — | — |
| Jalankan playbook | ✓ | ✓ | ✓ | ✓ | — | — |
| Setujui aksi otomatis (ban playbook) | ✓ | ✓ | ✓ | — | — | — |
| Kelola integrasi* | ✓ | — | — | — | — | — |
| Kelola pengguna & peran | ✓ | — | — | — | — | — |
| Lihat audit log | ✓ | ✓ | — | — | — | ✓ |

\* Izin sudah ada, fiturnya belum. Pengaturan playbook (mode, syarat) memakai izin "Kelola integrasi", jadi hanya administrator.

Administrator menambah, menghapus, dan menonaktifkan/mengaktifkan akun di halaman Administration.

## Arsitektur

```
Browser ──HTTPS──> Caddy (wazuh.toyspedia.fun)
                     └─ /soc-automation/*  ──> server/app.py (127.0.0.1:8081, user socauto)
                                                  ├─ Wazuh Indexer (loopback, akun hanya-baca)
                                                  └─ SQLite + users.json (/var/lib/soc-automation-dashboard)
```

Frontend memanggil `api/...` dengan URL **relatif** (Caddy membuang prefix `/soc-automation`). Backend Python standar, tanpa dependency.

## Struktur folder

| Path | Isi |
|---|---|
| `soc-monitoring.html` | Dashboard (dipasang di VPS sebagai `index.html`) |
| `server/app.py` | Backend: login, sesi, RBAC, API Wazuh |
| `server/login.html` | Halaman login |
| `server/manage_users.py` | CLI kelola akun di VPS |
| `server/fail2ban/` | Pembantu root (skrip + unit systemd) yang membuat snapshot status fail2ban |
| `google-search.html`, `vercel.json` | Halaman pencarian dan konfigurasi Vercel |
| `docs/` | Desain awal lab Wazuh (sebagian usang) |

## Deploy ke VPS

Layanan: `soc-automation-dashboard` (systemd) di `/opt/soc-automation-dashboard/`.

1. Salin file ke VPS: `server/app.py`, `server/login.html`, `server/manage_users.py`, dan `soc-monitoring.html` (sebagai `index.html`).
2. Cadangkan versi lama dulu (`cp -p x x.bak-...`), pasang dengan `install -o root -g socauto -m 640`, lalu `sudo systemctl restart soc-automation-dashboard`.
3. Cek: `healthz` 200, `api/overview` tanpa login 401, `/` menampilkan form login. Bila gagal, kembalikan cadangan.

Restart mengeluarkan semua pengguna (sesi disimpan di memori). Uji perubahan backend dulu di instance terpisah (port lain, sandbox systemd yang sama), bukan di layanan produksi.

## Analisis AI per alert

Klik sebuah alert di Alert Management, lalu **Analisis dengan AI** di kartu detail. Hasilnya penilaian (jinak, mencurigakan, berbahaya, atau perlu data lagi), bukti, langkah yang disarankan, dan kemungkinan false positive, dalam bahasa Indonesia. Hanya saran: dashboard tidak menjalankan tindakan apa pun dari hasil itu, dan model tidak diberi alat apa pun.

- **Penyedia:** API kompatibel OpenAI (`POST {AI_BASE_URL}/chat/completions`), default `https://ai.sumopod.com/v1`. Tanpa SDK dan tanpa paket tambahan di server.
- **Konfigurasi** (di `/etc/soc-automation/dashboard.env`): `AI_API_KEY` (wajib), `AI_MODEL` (default `claude-sonnet-4-6`), `AI_BASE_URL`, `AI_DAILY_LIMIT` (default 150 analisis per hari), `AI_MAX_TOKENS`. Pasang key lewat `read -rs` supaya tidak masuk riwayat shell atau chat.
- **Data yang dikirim ke penyedia:** rule, MITRE, nama dan ID agen, log mentah (dipotong 3.000 karakter), field data, hingga 15 alert terkait, skor AbuseIPDB dari cache, status daftar IOC, dan status fail2ban untuk IP sumber. Kredensial, sesi, dan konfigurasi server tidak ikut.
- **Keamanan:** isi log bisa dikendalikan penyerang, jadi dikirim sebagai data di dalam `<alert_data>` dengan tanda `<` di-escape dan instruksi eksplisit untuk mengabaikan perintah di dalamnya. Keluaran divalidasi dan ditampilkan sebagai teks.
- **Biaya:** hasil disimpan sehingga membuka ulang alert tidak memanggil model lagi; analisis ulang punya jeda 30 detik; ada batas harian. Yang boleh memicu analisis hanya peran dengan izin triage.

## Playbook: blokir IP sumber (Automation Center)

Playbook memblokir IP sumber serangan lewat fail2ban dan UFW di server ini. Mode, dari paling aman:

| Mode | Perilaku |
|---|---|
| Mati | Tidak mengevaluasi apa pun |
| Simulasi (bawaan) | Mencatat IP yang akan diblokir; tidak memblokir |
| Persetujuan manual | Membuat usulan; analis dengan izin approve (T3 ke atas) mengklik Setujui |
| Otomatis penuh | Memblokir langsung; hanya administrator yang bisa menyalakannya, dengan konfirmasi |

Syarat bisa diatur administrator: severity minimum, minimal N alert dalam W menit dari IP yang sama, agen yang dipantau, skor AbuseIPDB minimum (opsional), dan maksimal usulan per jam. Evaluasi berjalan tiap menit. Ban sementara (24 jam, diatur di jail), bisa dicabut dari tabel, dan semua tindakan tercatat di audit log. Ban aktif juga tampil di halaman Fail2ban.

**Pengaman dipaksakan oleh pembantu root, bukan dashboard.** Dashboard (`socauto`, tanpa hak root) hanya menaruh berkas permintaan kecil; `soc-ban-helper` (root) memeriksa ulang: hanya IP publik, daftar putih (`/etc/soc-automation/ban-policy.json`, hanya root yang bisa mengubah) dan alamat server ini tidak pernah diblokir, batas ban per jam dan total ban aktif, hanya satu jail (`beruk-playbook`), dan hanya aksi ban atau unban. Berkas permintaan dibaca tanpa mengikuti symlink dan harus dimiliki `socauto`. Jadi dashboard yang dibobol pun tidak bisa memblokir IP yang dilindungi.

Cakupan: hanya server tempat dashboard berjalan. Server lain (misalnya webserver) butuh Wazuh active response di agennya, yang mengubah konfigurasi Wazuh dan belum dibuat.

Pemasangan (sekali, di server, dari folder `server/playbook/`):

```bash
sudo install -o root -g root -m 644 beruk-playbook.conf /etc/fail2ban/filter.d/beruk-playbook.conf
sudo install -o root -g root -m 644 beruk-playbook.local /etc/fail2ban/jail.d/beruk-playbook.local
sudo fail2ban-client -t && sudo fail2ban-client reload
sudo install -o root -g root -m 750 soc-ban-helper /usr/local/sbin/soc-ban-helper
sudo install -o root -g root -m 644 ban-policy.json.example /etc/soc-automation/ban-policy.json   # lalu edit daftar putihnya
sudo install -d -o socauto -g socauto -m 770 /var/lib/soc-automation-dashboard/ban-requests
sudo install -d -o root -g socauto -m 750 /var/lib/soc-automation-dashboard/ban-results
sudo install -m 644 soc-ban-helper.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now soc-ban-helper
```

Isi `ban-policy.json` dengan IP Anda sendiri dan infrastruktur Anda sebelum mode selain Simulasi dinyalakan.

## Pembantu fail2ban

Socket dan database fail2ban hanya bisa dibuka root, sedangkan dashboard berjalan sebagai `socauto`. Karena itu `server/fail2ban/` berisi skrip kecil milik root yang membaca status fail2ban tiap 30 detik dan menulis satu berkas JSON (`/var/lib/soc-automation-dashboard/fail2ban.json`, `root:socauto`, mode 640). Dashboard hanya membaca berkas itu, tidak mendapat hak tambahan, dan halamannya hanya memantau (tanpa unban).

```bash
sudo install -o root -g root -m 750 server/fail2ban/soc-fail2ban-snapshot /usr/local/sbin/soc-fail2ban-snapshot
sudo install -m 644 server/fail2ban/soc-fail2ban-snapshot.service server/fail2ban/soc-fail2ban-snapshot.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now soc-fail2ban-snapshot.timer
```

Zona waktu server tidak dipakai di tampilan: waktu log dikonversi ke UTC oleh skrip, lalu ditampilkan dalam WIB (UTC+7).

## Kelola akun dari terminal

Administrator bisa mengelola akun dari dashboard. Untuk akun pertama atau mengubah peran/kata sandi:

```bash
sudo python3 /opt/soc-automation-dashboard/manage_users.py add budi --role admin
sudo python3 /opt/soc-automation-dashboard/manage_users.py role budi analyst_t2
sudo python3 /opt/soc-automation-dashboard/manage_users.py passwd budi
sudo python3 /opt/soc-automation-dashboard/manage_users.py disable budi
sudo python3 /opt/soc-automation-dashboard/manage_users.py list
```

Peran: `admin`, `manager`, `analyst_t3`, `analyst_t2`, `analyst_t1`, `readonly`. Kata sandi diminta lewat prompt (minimal 12 karakter), tidak pernah lewat argumen.

## Keamanan

- Hash kata sandi scrypt; cookie sesi `HttpOnly`, `SameSite=Lax`, `Secure` di belakang HTTPS; sesi habis setelah 2 jam tidak aktif atau 12 jam total.
- 5 percobaan login gagal per 15 menit (per IP dan per nama), cek `Origin` pada semua POST, CSP.
- Dashboard hanya membaca Wazuh dan tidak mengubah konfigurasinya.
- Jangan commit `users.json`, `dashboard.env`, atau berkas konfigurasi Caddy.

## Halaman pencarian

Mode **Cari** (diteruskan ke Google) dan **Tanya AI** (diteruskan ke claude.ai), saran dari riwayat pencarian (disimpan di browser), pencarian suara (Chrome/Edge), dan tampilan responsif. Buka langsung dengan klik dua kali `google-search.html`; tidak perlu server.

Di Vercel, `soc-monitoring` tidak punya backend sehingga menampilkan peringatan "Tidak bisa terhubung ke Wazuh" dan semua panel kosong.
