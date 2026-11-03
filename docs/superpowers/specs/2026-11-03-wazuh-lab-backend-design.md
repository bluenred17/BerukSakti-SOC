# Desain: Lab Wazuh sebagai Backend BerukSakti (v1)

Tanggal: 3 November 2026
Status: menunggu review pengguna

## 1. Tujuan

Mengganti data contoh di dashboard BerukSakti (`soc-monitoring.html`) dengan alert asli dari lab Wazuh, di belakang login, tanpa membuka port Wazuh ke internet.

**Kriteria sukses v1**

- Serangan simulasi di endpoint lab muncul sebagai alert di dashboard BerukSakti dalam < 1 menit.
- Modul **Alert Management**, **SOC Overview**, dan **SIEM Health** memakai data Wazuh; modul lain tetap data contoh dan diberi label "Data contoh".
- Status triage (assignee, status) tersimpan permanen dan tercatat di audit log.
- Hanya pengguna yang login yang bisa melihat data Wazuh; peran `viewer` hanya melihat field yang disamarkan.
- Ketujuh skenario uji di bagian 8 lulus di VPS sungguhan.

**Di luar lingkup v1:** FP Classifier / LLM (tahap berikutnya, mengikuti roadmap di `multi-agent-orchestration-report.md`), Incident/Case management dari data asli, playbook dan aksi otomatis, login Google/GitHub, reset password via email, peran T1/T2/T3 terpisah.

## 2. Keputusan yang sudah diambil

| Topik | Keputusan | Alasan |
|---|---|---|
| SIEM | Wazuh all-in-one (Docker single-node) | VPS 2 vCPU / 4–8 GB; Elastic self-managed tidak muat |
| Arsitektur | Dashboard + API di VPS (pendekatan A); Vercel tetap demo publik dengan data contoh | Satu origin → cookie sesi sederhana; kredensial dan port Wazuh tidak keluar dari VPS |
| Akses | Wajib login, beberapa pengguna dengan peran | Data lab tidak boleh publik (lihat kendala di PROGRESS.md) |
| Endpoint | Laptop Windows, VM korban lokal, VPS utama, VPS kecil tambahan | Variasi sumber: Windows, Linux, serangan internet asli, honeypot |

## 3. Topologi

```
Internet
   │
   ├─ :443 ─► Caddy (HTTPS otomatis, domain DuckDNS atau domain sendiri)
   │            └─► beruk-api (Node.js, 127.0.0.1:3000)
   │                  ├─ /, /login, /logout, /activate/:token
   │                  ├─ /api/*
   │                  └─ SQLite (users, sessions, alert_state, audit_log)
   │                        │ localhost
   │                        ▼
   │                  Wazuh single-node (Docker)
   │                  ├─ Indexer :9200      bind 127.0.0.1
   │                  ├─ Manager API :55000 bind 127.0.0.1
   │                  └─ Dashboard bawaan   127.0.0.1:5601 (port 443 container dipetakan ulang; akses via SSH tunnel)
   │
   └─ :1514/:1515 ─► Wazuh Manager ◄── agent (laptop, VM korban, VPS, VPS kecil)
```

**Firewall VPS:** terbuka hanya 22 (SSH key-only), 80/443, 1514, 1515.

**Anggaran RAM (VPS 4 GB):** Indexer ~1,5 GB (heap 1 GB), Manager ~0,6 GB, Wazuh Dashboard ~0,5 GB, beruk-api + Caddy ~0,15 GB, OS ~0,7 GB, ditambah swap 2–4 GB. Pada 8 GB heap Indexer dinaikkan ke 2 GB.

**Retensi:** ISM policy hapus indeks `wazuh-alerts-*` setelah 30 hari.

## 4. beruk-api

Layanan Node.js (LTS) tanpa framework berat; dependency dibatasi pada `better-sqlite3`, `argon2`, dan satu pustaka TOTP. Test memakai `node:test` bawaan.

### 4.1 Integrasi dengan dashboard

`soc-monitoring.html` tetap satu file. Versi yang disajikan dari VPS memuat `<script src="/api/live.js">` sebelum skrip utama; `live.js` berisi objek yang menimpa kunci-kunci `DATA` yang sudah tersambung (pola sama dengan `data/*.js`). Dashboard menandai setiap modul sebagai "Live (Wazuh)" atau "Data contoh". Versi Vercel tidak memuat `live.js` dan tidak berubah perilakunya.

### 4.2 Pemetaan Wazuh → `DATA`

| `DATA` | Sumber | Aturan |
|---|---|---|
| `alerts` | Indexer `wazuh-alerts-*`, 500 terbaru, `rule.level ≥ 5` | `id`=`_id`, `time`=`timestamp`, `rule`=`rule.description`, `source`=`rule.groups[0]`, `asset`=`agent.name`, `assignee`/`status` dari `alert_state` (default `''` / `New`) |
| severity | `rule.level` | 0–4 Low, 5–8 Medium, 9–11 High, 12–15 Critical |
| `alerts_daily` | `date_histogram` harian 14 hari × severity | |
| `alerts_by_tactic` | agregasi `rule.mitre.tactic` | `tactic_id` dari tabel nama → ID MITRE statis |
| `top_threats` | top 5 `rule.description` 7 hari vs 7 hari sebelumnya | `category`=`rule.groups[0]`, `change`=(kini−lalu)/lalu |
| `agents` | Manager API `GET /agents` | status, OS, versi, `lastKeepAlive` |
| `nodes` | Indexer `_cluster/health`, `_nodes/stats` | status, CPU, heap, disk |
| `log_sources` | agregasi `decoder.name` jam terakhir | `eps` = jumlah/3600; `Delayed` bila tak ada event 15 menit, `Down` bila 60 menit |
| `kpis.mttd_min`, `kpis.mttr_hours` | `alert_state` | kosong (tampilan kosong) bila belum ada data triage |
| `rbac` | konstanta peran di beruk-api | menggantikan contoh |

### 4.3 Endpoint

| Metode | Path | Peran | Isi |
|---|---|---|---|
| GET | `/login`, POST `/login` | publik | form email + password + TOTP |
| POST | `/logout` | login | hapus sesi |
| GET/POST | `/activate/:token` | publik (token) | set password + daftar TOTP |
| GET | `/` | login | `soc-monitoring.html` |
| GET | `/api/live.js` | login | penimpa `DATA` |
| GET | `/api/alerts?since=` | login | alert baru sejak waktu tertentu (polling 30 detik) |
| PATCH | `/api/alerts/:id` | admin, analyst | ubah `assignee`/`status`, tulis audit |
| GET | `/api/health` | login | status Wazuh, cache, ingestion |
| GET/POST/PATCH | `/api/users` | admin | daftar, buat (menghasilkan link aktivasi), nonaktifkan |
| GET | `/api/audit` | admin | audit log |

### 4.4 Skema SQLite

- `users(id, email, name, role, password_hash, totp_secret, active, created_at, last_login)`
- `activation_tokens(token_hash, user_id, expires_at, used_at)` — berlaku 48 jam, sekali pakai
- `sessions(id_hash, user_id, created_at, expires_at, ip, user_agent)`
- `alert_state(alert_id PK, assignee, status, updated_by, updated_at)`
- `audit_log(id, at, user_id, action, target, detail_json, ip)`
- `login_attempts(key, at)` — untuk rate limit

### 4.5 Cache dan polling

Hasil kueri Wazuh di-cache 30 detik di memori. Bila Wazuh gagal, API mengembalikan cache terakhir dengan `stale_since`.

## 5. Autentikasi dan otorisasi

| Peran | Lihat | Triage | Field sensitif | Kelola pengguna | Audit log |
|---|---|---|---|---|---|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `analyst` | ✓ | ✓ | ✓ | – | – |
| `viewer` | ✓ | – | disamarkan | – | – |

- **Field sensitif:** `srcip`/`dstip` publik, `data.srcuser`/`data.dstuser`, `full_log`, command line (`data.win.eventdata.commandLine`). Disamarkan di server untuk `viewer` (mis. `203.0.113.x`, `a***`).
- Password di-hash dengan argon2id; TOTP wajib untuk semua akun.
- Tidak ada pendaftaran mandiri. Admin pertama: `node beruk-api/cli.js create-admin`. Akun lain dibuat admin → link aktivasi sekali pakai.
- Cookie sesi `HttpOnly; Secure; SameSite=Strict`, kedaluwarsa 12 jam, disimpan sebagai hash di SQLite (bisa dicabut).
- Rate limit login: 5 gagal / 15 menit per IP dan per akun; semua login gagal masuk audit log.
- Permintaan yang mengubah data wajib header `X-CSRF-Token` yang cocok dengan sesi.
- Caddy menambahkan HSTS dan CSP (`script-src 'self'`; inline script dashboard diizinkan lewat hash SHA-256 yang dihitung beruk-api saat start, sehingga mengedit dashboard tidak perlu mengubah Caddyfile).
- beruk-api memakai user Wazuh read-only `beruk_reader` (Indexer: baca `wazuh-alerts-*` + monitor cluster; Manager API: baca agents). Kredensial di `.env`, tidak masuk Git.

## 6. Endpoint lab

| Endpoint | Pemasangan | Grup Wazuh |
|---|---|---|
| Laptop Windows | agent + Sysmon; Security, Sysmon, PowerShell/Operational; FIM folder Startup. **Tidak** dipakai untuk Atomic Red Team. | `windows` |
| VM korban Windows | agent + Sysmon; target Atomic Red Team; snapshot sebelum uji | `windows`, `victim` |
| VM korban Ubuntu | agent + auditd | `linux`, `victim` |
| VPS utama | agent lokal; SSH auth, FIM `/etc` | `linux`, `server` |
| VPS kecil | agent + Nginx (web korban) atau Cowrie (honeypot SSH) | `linux`, `honeypot` |

Enrollment memakai password (`authd.pass`). Konfigurasi per grup lewat `agent.conf` terpusat. Agent di balik NAT rumah tidak butuh port forwarding.

## 7. Penanganan error

| Kondisi | Perilaku |
|---|---|
| Indexer tidak merespons | Kirim cache terakhir + `stale_since`; dashboard menampilkan banner kuning "Data Wazuh terakhir diperbarui X menit lalu". Tidak pernah diam-diam kembali ke data contoh. |
| Manager API mati | Modul agent menampilkan tampilan kosong yang jujur; modul lain tetap jalan |
| Sesi habis / tidak login | 401 untuk `/api/*`, redirect ke `/login` untuk halaman |
| Peran tidak cukup | 403, dicatat di audit log |
| Ingestion berhenti (> 30 menit tanpa alert baru padahal ada agent aktif) | Peringatan di SIEM Health |
| Dokumen alert tanpa field yang diharapkan | Field diisi `—`, alert tetap ditampilkan; jumlah dokumen cacat dilaporkan di `/api/health` |

## 8. Pengujian

**Otomatis (`node --test beruk-api/test`)**

- Unit: pemetaan dokumen Wazuh → `DATA` (fixture contoh alert SSH, Sysmon, FIM), pemetaan level → severity, penyamaran field per peran, rate limit, validasi `PATCH`.
- Integrasi: login + TOTP, sesi kedaluwarsa, CSRF, `PATCH` analyst sukses, `PATCH` viewer 403, Indexer mati → `stale_since`. Memakai SQLite in-memory dan stub HTTP Wazuh.

**Manual di VPS (hasil dicatat di PROGRESS.md)**

| # | Aksi | Hasil yang diharapkan |
|---|---|---|
| 1 | 10 login SSH gagal ke VPS kecil | Alert brute force (5710/5712) muncul di antrean < 1 menit, severity ≥ Medium |
| 2 | Atomic T1059.001 di VM Windows | Alert dengan MITRE T1059; taktik Execution bertambah |
| 3 | Atomic T1053.005 di VM Windows | Alert scheduled task; taktik Persistence bertambah |
| 4 | Ubah file di `/etc` VPS utama | Alert FIM (550) |
| 5 | Hentikan agent VM | SIEM Health menampilkan agent Down/Disconnected |
| 6 | Analyst ubah status alert lalu refresh | Status bertahan; tercatat di audit log |
| 7 | Viewer buka alert #1 dan coba `PATCH` | IP/username tersamar; `PATCH` ditolak 403 |

## 9. Struktur repo

```
beruk-api/
  server.js
  cli.js
  routes/        # auth, alerts, live, users, health
  wazuh/         # klien Indexer & Manager API, pemetaan ke DATA
  auth/          # password, totp, sesi, rate limit, csrf, peran
  db/            # skema & migrasi SQLite
  test/          # node:test + fixtures/
deploy/
  docker-compose.yml   # Wazuh single-node, heap dibatasi, port bind 127.0.0.1
  Caddyfile
  beruk-api.service    # systemd
  agents/              # agent.conf per grup, config Sysmon
docs/lab-wazuh.md      # setup VPS, firewall, swap, enrollment, skenario uji, backup
```

Perubahan di `soc-monitoring.html`: memuat `/api/live.js` bila ada, label "Live (Wazuh)" / "Data contoh" per modul, banner data basi, polling `/api/alerts`, `PATCH` saat penugasan/status diubah, redirect 401 ke `/login`. Perilaku di Vercel tidak berubah.

## 10. Operasional

- Backup harian: file SQLite dan konfigurasi Wazuh (`ossec.conf`, `agent.conf`, rule/decoder kustom) ke `/var/backups/beruk`, simpan 14 hari.
- Wazuh Dashboard bawaan diakses dengan `ssh -L 5601:127.0.0.1:5601`.
- Update Wazuh mengikuti rilis minor; versi dikunci di `docker-compose.yml`.

## 11. Pertanyaan terbuka

- Domain: DuckDNS (gratis) atau domain sendiri. Desain berlaku untuk keduanya; dipilih saat setup.
- VPS kecil: Nginx web korban atau Cowrie honeypot (atau keduanya bila RAM cukup). Tidak mengubah desain beruk-api.
