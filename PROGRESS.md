# PROGRESS — BerukSakti

Rangkuman status proyek per 3 November 2026, sampai penambahan data publik EuRepoC (lanskap ancaman global).

- Repo: https://github.com/bluenred17/BerukSakti-SOC (branch `master`)
- Website: https://beruksakti-soc.vercel.app

---

## 1. Tujuan aplikasi dan requirement utama

BerukSakti terdiri dari dua halaman web statis:

1. **Halaman pencarian BerukSakti** (`google-search.html`): halaman depan pencarian pribadi bergaya Perplexity. Pengguna bisa memilih mencari di web (diteruskan ke Google) atau bertanya ke AI (diteruskan ke claude.ai).
2. **Dashboard Beruk Sakti Monitoring** (`soc-monitoring.html`): dashboard Security Operations Center (SOC) untuk memantau alert, insiden, intelijen ancaman, otomasi, dan kesehatan SIEM, dilengkapi chatbox Asisten SOC di sisi kanan.

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

- Chatbox AI di sisi kanan dashboard (diputuskan: simulasi dulu, menjawab dari data dashboard).
- Bisa dibuka publik oleh siapa pun lewat website.
- Tampilan berfungsi di desktop dan HP.
- Dashboard mengikuti rancangan **SOC Automation** di `multi-agent-orchestration-report.md`: Elastic Security sebagai SIEM, LLM sebagai **FP Classifier** (prioritas: mengurangi false positive), alur Triage → Analisa → Reporting, dan human-in-the-loop. Laporan itu menjadi roadmap backend; dashboard menjadi tampilannya.

---

## 2. Tech stack dan struktur folder

**Tech stack**

- HTML, CSS, dan JavaScript murni (vanilla), tanpa framework, tanpa build step, tanpa library eksternal.
- Grafik digambar sendiri dengan SVG; peta ancaman di latar belakang dashboard memakai Canvas 2D.
- Data contoh disimpan sebagai objek `DATA` di dalam `soc-monitoring.html`.
- Data publik (dataset riset) diolah offline oleh skrip Node.js `scripts/build-data.js` dari folder `raw/` (tidak masuk Git) menjadi file ringkas di `data/`, yang dimuat halaman lewat `<script src>`.
- Git + GitHub untuk versi kode.
- Vercel untuk hosting statis, deploy otomatis setiap `git push` ke `master`.

**Struktur folder**

```
D:\Project\aibuilder\
├── .git/
├── README.md              # Penjelasan proyek (perlu diperbarui, lihat bagian 6)
├── PROGRESS.md            # File ini
├── multi-agent-orchestration-report.md  # Rancangan SOC Automation (roadmap backend), belum di-commit
├── google-search.html     # Halaman pencarian BerukSakti (gaya Perplexity)
├── soc-monitoring.html    # Dashboard Beruk Sakti Monitoring, 8 modul + Asisten SOC
├── vercel.json            # Konfigurasi Vercel: cleanUrls + rewrite "/" ke halaman pencarian
├── .gitignore             # Mengecualikan raw/ dan .claude/launch.json
├── data/
│   └── eurepoc.js         # Ringkasan EuRepoC (hasil build, ±30 KB)
├── scripts/
│   ├── build-data.js      # Mengolah raw/ menjadi data/
│   └── lib/csv.js         # Pembaca CSV sederhana
└── raw/                   # Dataset mentah, TIDAK masuk Git
    ├── eurepoc/           # eurepoc_global_dataset_1_3.csv, eurepoc_codebook_1_2.pdf
    └── unsw-nb15/         # (kosong, menunggu diunduh pengguna)
```

Setiap halaman berdiri sendiri dalam satu file (HTML, CSS, dan JS jadi satu).

---

## 3. Daftar file yang sudah dibuat

| File | Isi | Ukuran |
|---|---|---|
| `google-search.html` | Halaman pencarian BerukSakti bergaya Perplexity | ±380 baris |
| `soc-monitoring.html` | Dashboard SOC 8 modul + chatbox Asisten SOC + data contoh + peta ancaman animasi | ±3.130 baris |
| `vercel.json` | `cleanUrls: true`, rewrite `/` → `/google-search` | 6 baris |
| `README.md` | Penjelasan proyek (masih versi lama) | — |
| `PROGRESS.md` | Rangkuman progres ini | — |
| `multi-agent-orchestration-report.md` | Rancangan SOC Automation: pipeline Elastic → LLM FP Classifier, skema JSON, aturan keputusan, roadmap 5 fase (dibuat pengguna, belum di-commit) | ±130 baris |
| `scripts/build-data.js` | Mengolah dataset publik di `raw/` menjadi ringkasan di `data/`; bagian UNSW-NB15 masih kerangka | ±170 baris |
| `scripts/lib/csv.js` | Pembaca CSV (kutip, baris baru di dalam kutip) | ±40 baris |
| `data/eurepoc.js` | Ringkasan EuRepoC: total, per tahun, negara, pelaku, sektor, MITRE, 40 insiden terbaru, 23 insiden Indonesia | ±30 KB |
| `.gitignore` | `raw/`, `.claude/launch.json` | 2 baris |

**Riwayat commit**

| Commit | Isi |
|---|---|
| `d9b0f3d` | Commit awal: dashboard Beruk Sakti Monitoring dan file proyek |
| `71dcaf2` | Ubah tampilan `google-search.html` menjadi bergaya Perplexity |
| `15193d4` | Tambah `vercel.json` agar halaman utama membuka `google-search.html` |
| `b35973d` | Perbaiki rewrite Vercel: tujuan tanpa `.html` karena `cleanUrls` aktif |
| `51c4c65` | Tambah sidebar panel di dashboard |
| `b116fd0` | Kembangkan dashboard menjadi 8 modul SOC |
| `986ad77` | Tambah PROGRESS.md |
| `1ed0e4f` | Sesuaikan dashboard dengan laporan orkestrasi (FP Classifier, fail-safe, tuning rule, metrik FP) |
| `25b7672` | Rapikan daftar skor risiko di AI Investigation agar kolom sejajar |
| `e7577f9` | Tambah chatbox Asisten SOC (simulasi) di sisi kanan dashboard |

**URL publik (sudah dicek mengembalikan HTTP 200)**

| URL | Halaman |
|---|---|
| https://beruksakti-soc.vercel.app/ | Halaman pencarian |
| https://beruksakti-soc.vercel.app/google-search | Halaman pencarian |
| https://beruksakti-soc.vercel.app/soc-monitoring | Dashboard (modul bisa dibuka langsung dengan `#overview`, `#alerts`, `#ai`, `#intel`, `#incidents`, `#automation`, `#siem`, `#admin`) |

---

## 4. Fitur yang sudah selesai dan sudah diuji

Pengujian dilakukan di browser pane aplikasi Claude (ukuran desktop 1280×800 dan 1440×860, HP 375×812), dengan pengecekan console error dan pengujian interaksi lewat JavaScript. Tidak ada test otomatis di repo.

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
- [x] **1. SOC Overview**: 6 KPI, grafik tren alert 14 hari (tooltip), distribusi severity 7 hari dengan perbandingan minggu sebelumnya, tabel ancaman teratas, grafik taktik MITRE ATT&CK, **metrik pengurangan false positive** (FP rate, miss rate, waktu analis per alert, alert yang butuh sentuhan manusia, usulan tuning disetujui; warna sesuai arah perbaikan), dan **Top 10 rule paling berisik** dengan FP rate.
- [x] **2. Alert Management**: antrean 14 alert, filter (cari, severity, status, analis), ubah analis dan status triage langsung di tabel, kolom **Label AI** (`ai-triage:fp-suspected` / `tp-likely` / `needs-review`). Diuji: penugasan menurunkan badge 5 → 4; filter Critical menampilkan 3 baris; 3 alert punya label AI sesuai aturan keputusan.
- [x] **3. AI Investigation** (mengikuti laporan orkestrasi): data FP Classifier memakai skema JSON laporan (`verdict`, `confidence`, `reasoning`, `evidence`, `recommended_action`, `tuning_suggestion`); **aturan keputusan** (label FP hanya bila confidence ≥ 0,9, ada bukti, dan aset non-kritikal; selain itu eskalasi); **fail-safe** (output tidak valid atau tanpa bukti selalu dieskalasi); 5 KPI (diduga FP, dieskalasi, kesesuaian dengan analis, miss rate, golden set); roadmap 5 fase dengan fase berjalan "Mode bayangan"; daftar skor risiko dengan kolom ID, nama, bar, dan angka yang sejajar di semua baris; kartu per alert/insiden berisi alasan, bukti berupa field log, korelasi log, rekomendasi, usulan tuning, dan output JSON. Diuji: 7 investigasi menghasilkan 2 label FP dan 5 eskalasi (1 karena fail-safe pada ALR-90411 yang tanpa bukti).
- [x] **4. Threat Intelligence**: lookup IOC dengan deteksi tipe (IPv4, domain, MD5/SHA-1/SHA-256), hasil reputasi dan enrichment (skor, negara, ASN, tag, insiden terkait), tabel feed, tabel IOC yang bisa diklik. Diuji: IOC dikenal, IP tidak dikenal, dan format salah.
- [x] **Lanskap ancaman global (data nyata EuRepoC)** di Threat Intelligence: 5 KPI (3.414 insiden 2000–2024, 700 pada 2024, 1.014 terkait aktor negara, 502 ransomware dengan 98 memakai zero-day, 23 menyasar Indonesia), grafik insiden per tahun dengan tooltip jenis insiden, negara sasaran, asal pelaku dan kategori pelaku, sektor sasaran, teknik MITRE initial access/impact, daftar insiden (40 terbaru global atau 23 insiden Indonesia), dan atribusi sumber + lisensi. Bagian ini tersembunyi otomatis kalau `data/eurepoc.js` tidak ada. Asisten SOC bisa menjawab "lanskap ancaman global" dan "serangan ke Indonesia". Diuji lewat server lokal (desktop dan HP, tanpa error console).
- [x] **5. Incident Management**: tabel kasus dengan SLA (lewat SLA merah), timeline investigasi per kasus (klik baris), tabel insiden yang bisa dicari dan diurutkan. Diuji: klik kasus mengganti timeline.
- [x] **6. Automation Center**: tombol Setujui/Tolak aksi, **antrean persetujuan tuning rule** dari FP Classifier (exception/ubah kondisi, masa berlaku, dasar usulan; exception dengan wildcard ditandai "cakupan luas"), playbook dengan toggle aktif, riwayat eksekusi. Diuji: menyetujui APR-311 menurunkan badge dan mengubah status eksekusi menjadi Running; menyetujui TUN-042 menurunkan badge 6 → 5 dan tercatat di audit log.
- [x] **7. SIEM Health**: status cluster (Green/Yellow/Red), CPU/heap/disk tiap node, ingestion per sumber log, status agen, error pipeline.
- [x] **8. Administration**: tabel pengguna (MFA, status), matriks RBAC, integrasi dengan toggle, audit log yang ikut mencatat perubahan di halaman. Diuji: audit log bertambah setelah penugasan dan persetujuan.
- [x] **Asisten SOC (chatbox kanan, simulasi)**: panel di sisi kanan yang bisa dibuka/tutup (tombol "Tanya AI", ✕ tutup, ↺ percakapan baru, Esc menutup di layar sempit); menempel di kanan pada layar > 1100 px dan terbuka otomatis pada layar ≥ 1440 px, menutupi halaman pada layar sempit. Menjawab dari objek `DATA`: ringkasan kondisi SOC, detail ID (`INC-`, `ALR-`, `CASE-`, `APR-`, `TUN-`), reputasi IOC (IP/domain/hash), insiden kritis & SLA, alert belum ditugaskan, false positive, rule berisik & tuning, persetujuan, kesehatan SIEM, playbook, KPI, admin, dan "jelaskan halaman ini". Jawaban punya tombol yang membuka modul terkait (mis. timeline kasus, Lookup IOC). Pertanyaan di luar data ditolak dengan jelas. Diuji: 18 jenis pertanyaan, tombol navigasi, tampilan desktop 1440 px dan HP, tanpa error console.

### Deploy

- [x] Repo di-push ke GitHub.
- [x] Project Vercel `beruksakti-soc` (team BerukSakti) terhubung ke repo; deploy otomatis saat push ke `master`. Diuji: tiga URL di atas mengembalikan 200 (dicek ulang 3 November 2026), dan versi terbaru dengan Asisten SOC sudah tayang.

---

## 5. Fitur yang belum selesai

- [ ] **Data asli**: selain lanskap ancaman global (EuRepoC), semua angka, nama, IOC, dan hasil "AI" adalah data contoh yang ditulis langsung di objek `DATA`. Belum terhubung ke SIEM, EDR, feed intelijen, atau model AI sungguhan.
- [ ] **UNSW-NB15** belum dipakai: menunggu pengguna mengunduh dari SharePoint UNSW (disarankan `UNSW-NB15_1.csv` + `UNSW-NB15_features.csv`, karena training/testing set tidak punya kolom waktu dan IP) ke `raw/unsw-nb15/`. Rencana: alert dan tren di SOC Overview/Alert Management, dengan tanggal digeser ke 14 hari terakhir dan diberi keterangan sumber.
- [ ] **Asisten SOC dengan AI sungguhan**: chatbox masih simulasi berbasis kata kunci. Untuk memakai model sungguhan, `askAssistant()` diganti dengan panggilan ke backend (mis. `/api/chat` yang memanggil Claude API dengan API key di environment variable Vercel), setelah dashboard punya login dan pembatas pemakaian.
- [ ] **Pipeline SOC Automation** dari laporan orkestrasi belum dibangun: orchestrator (n8n/Python), dedup & grouping, enrichment ES|QL, pre-filter deterministik, panggilan LLM, validasi skema, dan penulisan tag balik ke Elastic. Dashboard baru menampilkan bentuk hasilnya.
- [ ] **Fase 0–1 roadmap** (analisis FP 30–90 hari, golden set berlabel) belum dikerjakan; angka fase, kesesuaian, dan golden set di dashboard adalah contoh.
- [ ] **Keputusan terbuka dari laporan**: volume alert per hari, jumlah analis, versi/lisensi Elastic, pilihan model LLM (cloud atau self-hosted), kebijakan privasi data.
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
| Pratinjau `data:` URL di browser pane aplikasi Claude tidak bisa memuat `data/eurepoc.js` (path relatif). | Lanskap ancaman global tidak muncul di pratinjau itu. Uji lewat server lokal (`.claude/launch.json`, port 8137) atau Vercel. Membuka file langsung dengan klik dua kali tetap jalan. | Dibiarkan, cara uji dicatat |
| Lisensi dataset non-komersial (EuRepoC CC BY-NC 4.0; UNSW-NB15 hanya untuk riset akademik). | BerukSakti harus tetap proyek non-komersial (sudah dikonfirmasi pengguna) dan sumber wajib dicantumkan. | Dipatuhi |
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
10. **Perubahan data di halaman sengaja tidak disimpan** (penugasan, persetujuan, toggle, percakapan chat) karena ini data contoh bersama; penyimpanan sungguhan butuh backend. `localStorage` hanya dipakai untuk preferensi tampilan per browser (mode Cari/Tanya AI di halaman pencarian, panel Asisten SOC terbuka atau tertutup).
11. **Data AI mengikuti skema JSON FP Classifier dari laporan orkestrasi**, supaya output LLM nanti bisa ditampilkan tanpa diubah. Field tambahan (`risk`, `asset_critical`, `correlated`, `next_steps`) diperlakukan sebagai hasil enrichment pipeline, bukan output LLM.
12. **Aturan keputusan dan fail-safe dijalankan di dashboard (`decide_ai`)**, bukan dipercaya dari LLM: output tidak valid atau tanpa bukti selalu jadi `needs-review`. Di backend nanti aturan yang sama harus diterapkan sebelum tag ditulis ke Elastic.
13. **Tuning rule selalu lewat persetujuan manusia**, dan exception yang memakai wildcard ditandai agar ditinjau ulang (prinsip "exception sempit + masa berlaku" dari laporan).
14. **Asisten SOC dibuat simulasi dulu** (dipilih pengguna): tanpa API key dan biaya, aman selama dashboard publik. Semua jawaban lewat satu fungsi `askAssistant(text)` yang mengembalikan blok `{p}`, `{ul}`, `{go}`, sehingga backend AI nanti cukup mengembalikan format yang sama. Status buka/tutup panel diingat per browser di `localStorage`.
15. **Data publik diolah offline, bukan dimuat mentah**: dataset mentah disimpan di `raw/` (di luar Git), diringkas oleh `scripts/build-data.js` menjadi `data/*.js` (`window.EUREPOC = {...}`) yang kecil. Dimuat dengan `<script src>` (bukan `fetch`) supaya tetap jalan saat file dibuka langsung. Setiap data publik wajib menampilkan sumber dan lisensinya, dan dibedakan jelas dari data SOC contoh.

---

## 8. Task berikutnya yang harus dikerjakan

Urutan yang disarankan:

1. **Olah UNSW-NB15** begitu file ada di `raw/unsw-nb15/`: lengkapi `buildUnsw()` di `scripts/build-data.js`, hasilkan `data/unsw-nb15.js`, lalu ganti data contoh tren dan antrean alert dengan data itu (tanggal digeser, sumber dicantumkan).
2. **Perbarui `README.md`**: jelaskan kedua halaman, URL Vercel, cara deploy, cara menjalankan `node scripts/build-data.js`, dan sumber data.
3. **Jawab keputusan terbuka dari laporan orkestrasi** (volume alert, jumlah analis, versi Elastic, model LLM, kebijakan privasi), lalu jalankan **Fase 0**: ekspor alert 30–90 hari dari Elastic, hitung Top 10 rule paling berisik, dan catat baseline FP rate, waktu analis, MTTD/MTTR. Hasilnya menggantikan data contoh di SOC Overview.
4. **Tambahkan autentikasi** sebelum data asli masuk (mis. Vercel Password Protection, SSO, atau login sendiri), lalu terapkan RBAC yang sudah ada di modul Administration.
5. **Bangun pipeline FP Classifier** (n8n/Python di server sendiri, bukan di Vercel) sesuai laporan: dedup, enrichment, pre-filter, LLM dengan output JSON tervalidasi, aturan keputusan + fail-safe yang sama dengan `decide_ai`, lalu backend kecil yang menyediakan hasilnya ke dashboard dalam bentuk objek `DATA`.
6. **Sambungkan Asisten SOC ke AI sungguhan** setelah login ada: endpoint backend (mis. Vercel Serverless Function `/api/chat`) yang memanggil Claude API dengan API key di environment variable Vercel, diberi konteks data dashboard, dibatasi pemakaiannya, lalu `askAssistant()` diarahkan ke endpoint itu dengan format blok yang sama.
7. **Simpan perubahan pengguna** (penugasan, status triage, persetujuan aksi dan tuning, toggle, audit log) ke database lewat backend.
8. **Sambungkan aksi nyata**: lookup IOC ke API reputasi, persetujuan aksi ke mesin SOAR/playbook, persetujuan tuning ke exception rule di Elastic, toggle integrasi ke konfigurasi asli.
9. **Refresh data otomatis** (polling berkala) dan tampilkan waktu pembaruan terakhir.
10. **Lengkapi halaman pencarian**: tujuan untuk menu Pustaka (mis. riwayat pencarian) dan link footer.
11. **Pertimbangkan memecah `soc-monitoring.html`** (±3.130 baris) menjadi file CSS/JS/data terpisah begitu mulai terhubung ke API.
12. **Opsional**: commit `multi-agent-orchestration-report.md` ke repo sebagai dokumen desain; aktifkan 2FA di akun Vercel; ganti nama branch ke `main` bila diinginkan.
