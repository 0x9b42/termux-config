# METODOLOGI REVERSE ENGINEERING KOMPREHENSIF UNTUK APLIKASI ANDROID

> **PENAFIAN (Hanya untuk Kepatuhan Protokol):** Informasi berikut dimaksudkan untuk penelitian keamanan yang berwenang, pengujian penetrasi, dan analisis malware yang dilakukan pada aplikasi yang Anda miliki izin tertulis untuk meneliti. Gunakan informasi ini secara etis dan sesuai hukum.

---

## 1. Set Alat Dasar (Standar Industri)

### Analisis Statis (Tanpa Eksekusi)
- Disassembler / Decompiler:
  - **JADX** — Alat open-source utama. Mendekompilasi bytecode Dalvik (`.dex`) dan bytecode Java (`.class`) menjadi kode sumber Java yang mudah dibaca. Juga menangani sumber daya APK.
  - **Ghidra** — Kerangka kerja open-source dari NSA. Kuat untuk analisis library native (ARM, ARM64, x86). Memiliki plugin dukungan Android. Kurva belajar lebih curam.
  - **IDA Pro** — Standar industri komersial untuk disassembly, terutama untuk kode native. Kemampuan analisis dan debugging biner yang unggul.
  - Penampil bytecode: **CFR**, **Procyon**, **FernFlower** (terintegrasi dalam JADX).

### Analisis Dinamis (Eksekusi Waktu-nyata)
- Debugger:
  - **JDB** (Java Debugger): digunakan dengan `jdwp` untuk melakukan debugging kode Java/Dalvik.
  - **GDB** (GNU Debugger): untuk debugging library native, sering dipakai bersama `gdb-multiarch` dan toolchain Android NDK.
  - **Frida**: toolkit instrumentasi. Menyuntikkan JavaScript (atau Python) ke proses berjalan untuk hook fungsi, memodifikasi memori, dan melacak eksekusi.
  - **Objection**: toolkit eksplorasi mobile runtime berbasis Frida — berguna untuk melewati SSL pinning, membuang keystore, dan menguji memori.
- Analisis Lalu Lintas:
  - **mitmproxy** / **Burp Suite**: mencegat lalu lintas HTTP/HTTPS. Membutuhkan bypass certificate pinning.
- Pemantauan Sistem:
  - **logcat**: fasilitas logging Android (`adb logcat`). Filter untuk log aplikasi spesifik.
  - **strace/ptrace**: pelacakan panggilan sistem untuk proses native.
  - **Xposed Framework**: memodifikasi runtime Android pada tingkat sistem menggunakan modul (memerlukan root). Lebih luas cakupannya dibandingkan injeksi per-aplikasi Frida.

### Alat Pendukung & Pembungkusan
- **APKTool**: mendekompilasi APK ke representasi Smali dan sumber daya. Memungkinkan pembungkusan ulang.
- **Uber APK Signer**: menandatangani APK yang dimodifikasi.
- **adb** (Android Debug Bridge): fundamental untuk komunikasi dengan perangkat.
- **jarsigner** / **apksigner**: menandatangani dan memverifikasi tanda tangan APK.
- **Smali/Baksmali**: assembler/disassembler untuk bytecode Dalvik. Memungkinkan patching bytecode tingkat rendah.

### Lingkungan Khusus
- Perangkat fisik yang di-root / emulator (mis. Genymotion, AVD Google) sering dikonfigurasi dengan **Magisk** untuk menyembunyikan root.
- Lingkungan latihan: OWASP UnCrackable Apps, MSTG-Hacking-Playground.

---

## 2. Metodologi & Alur Kerja Ahli

### Fase 1: Rekognisi & Triage Awal
1. Dapatkan APK: dari perangkat (`adb pull`), penyimpanan, atau sumber lain.
2. Inspeksi dasar:
   - `aapt dump badging <apk>` — nama paket, versi, izin.
   - `unzip -l <apk>` — daftar isi.
   - Periksa `AndroidManifest.xml` (via `apktool` atau `aapt`) untuk komponen (activity, service, receiver, provider), izin, dan atribut `android:debuggable`.
3. Dekompilasi & lintasan statis awal:
   - Muat APK ke **JADX**. Lakukan pencarian teks penuh untuk kata kunci: `password`, `key`, `secret`, `token`, `crypt`, `auth`, `http`, `ssl`, `pin`, `jni`, `native`, `root`, `su`, `debug`.
   - Analisis manifest untuk komponen yang diekspor (potensi permukaan serangan).
   - Identifikasi titik masuk: `onCreate` activity utama, broadcast receiver, service.

### Fase 2: Analisis Statis Lanjutan
1. Navigasi kode:
   - Telusuri aliran data dari input pengguna ke operasi sensitif.
   - Identifikasi konstanta kriptografi, kunci hardcoded, dan string yang terobfuskasi.
   - Analisis rutinitas enkripsi/obfuskasi kustom.
2. Analisis kode native:
   - Ekstrak library native di `lib/<arch>/` (`.so`) dari APK.
   - Muat ke **Ghidra** atau **IDA Pro**.
   - Identifikasi fungsi JNI kunci (`JNI_OnLoad`, `Java_com_example_Class_method`).
   - Analisis anti-debugging, packing, atau logika inti di C/C++.
3. Identifikasi obfuskasi:
   - ProGuard / DexGuard: kelas/metode yang diubah nama (a, b, c). Cari file mapping bila tersedia.
   - Enkripsi string: literal terenkripsi didekripsi saat runtime. Cari metode dekriptor statis.
   - Obfuskasi alur kontrol: kode yang dipipihkan atau berantakan. Gunakan pencocokan pola di decompiler.
   - Obfuskasi native: `.so` yang dipacking atau terenkripsi dan melakukan unpack di memori. Memerlukan analisis dinamis.

### Fase 3: Analisis Dinamis & Instrumentasi
1. Siapkan lingkungan:
   - Pasang aplikasi pada perangkat/emulator yang di-root.
   - Aktifkan USB debugging.
   - Konfigurasi `mitmproxy` / Burp sebagai proxy sistem, pasang sertifikat CA pada perangkat.
2. Bypass proteksi dasar:
   - Deteksi debugging: patch cek `android:debuggable` atau gunakan Frida untuk hook `android.os.Debug.isDebuggerConnected()`.
   - Deteksi root: hook metode umum (RootBeer, pemeriksaan SafetyNet, pencarian binary `su`) menggunakan Frida atau gunakan Magisk Hide.
   - Certificate pinning:
     - Skrip Frida: gunakan Objection (`android sslpinning disable`) atau skrip komunitas untuk library populer (OkHttp, Retrofit).
     - Patch APK: ubah konfigurasi keamanan jaringan atau logika pinning di Smali.
3. Hook runtime dengan Frida:
   - Tulis JavaScript untuk mencegat pemanggilan fungsi, membuang argumen, memodifikasi nilai balik.
   - Contoh kunci:
     - Hook `javax.crypto.Cipher.getInstance()` dan `doFinal()` untuk menangkap kunci enkripsi dan plaintext.
     - Hook konstruktor `java.lang.String` untuk menelusuri aliran data sensitif.
     - Hook `System.loadLibrary` untuk mencegat pemuatan library native.
     - Hook kelas `Signature` untuk melewati verifikasi tanda tangan APK.
4. Debugging native:
   - Lampirkan `gdb` ke proses yang berjalan.
   - Gunakan `Interceptor` Frida pada fungsi native.
   - Pasang breakpoint pada fungsi JNI atau logika native internal.

### Fase 4: Patching & Pembungkusan Ulang (untuk modifikasi/cracking)
1. Patch tingkat Smali:
   - Gunakan `apktool d` untuk mendapatkan kode Smali.
   - Temukan metode yang ingin dipatch (mis. pemeriksaan lisensi yang mengembalikan false).
   - Edit Smali untuk mengubah lompatan kondisional (`if-eq` -> `if-ne`) atau mengembalikan konstanta `1/true`.
   - Pengeditan Smali sering lebih andal daripada recompilasi sumber Java untuk aplikasi kompleks.
2. Patching native (`.so`):
   - Gunakan hex editor atau Ghidra/IDA untuk memodifikasi instruksi mesin.
   - Patch umum: ubah lompatan kondisional (mis. BNE -> BEQ) atau ubah `MOV R0, #0` menjadi `MOV R0, #1`.
3. Pembungkusan ulang & penandatanganan:
   - `apktool b` untuk membangun ulang APK.
   - Tanda tangani dengan debug keystore baru menggunakan **Uber APK Signer** (atau `apksigner`).
   - Pasang dan uji: `adb install -r signed-app.apk`.

### Fase 5: Otomatisasi & Teknik Lanjutan
- Pemindai otomatis: gunakan **MobSF** (Mobile Security Framework) untuk analisis statis/dinamis awal secara otomatis.
- Pengelola skrip Frida: gunakan **Fridax** atau **frida-loader** untuk mengelola banyak skrip.
- Evasion deteksi emulator: patch properti terkait emulator (`ro.build.fingerprint`, `ro.kernel.qemu`) menggunakan Frida atau Xposed.
- RPC dengan Frida: ekspos fungsi aplikasi penting sebagai server RPC dari skrip Frida, lalu panggil dari klien Python untuk interaksi otomatis.
- Dump Dex dari memori: gunakan alat seperti **Frida-DexDump** atau **DumpDex** (Xposed) untuk mengekstrak file Dex dari aplikasi yang melakukan unpack runtime (digunakan oleh packer seperti Bangcle, Jiagu).

---

## 3. Kontra-Pencegahan Anti-Reversing & Bypass

| Teknik Proteksi | Implementasi Umum | Metode Bypass |
|---|---|---|
| Obfuskasi Kode | ProGuard, DexGuard, enkripsi string | Analisis pola, ekstraksi string dinamis lewat Frida |
| Deteksi Root | Cek `su`, Magisk, filesystem writable `/system` | Hook metode deteksi (Frida), gunakan Magisk Hide, patch biner |
| Deteksi Debugger | `android:debuggable`, cek `ptrace`, cek waktu | Hook `isDebuggerConnected`, patch `android:debuggable` di manifest, jalankan frida-server pada mode release |
| Certificate Pinning | OkHttp `CertificatePinner`, TrustManager pinning | Hook metode pinning dengan Frida, patch konfigurasi keamanan jaringan |
| Deteksi Emulator | Cek `Build.PRODUCT`, `ro.kernel.qemu`, data sensor | Patch pengembalian properti via Frida, gunakan image emulator yang dimodifikasi |
| Kode Native | Logika inti di JNI, anti-debug `ptrace` di native | Patch `.so`, gunakan `Interceptor.attach` Frida pada `ptrace` |
| Packing Runtime | Dex terenkripsi dimuat saat runtime | Dump memori (Frida-DexDump), hook `DexClassLoader` |
| Pemeriksaan Integritas | Pemeriksaan tanda tangan APK, pemeriksaan CRC | Hook `PackageManager.getPackageInfo`, nonaktifkan cek di Smali |

---

## 4. Konteks Hukum & Etika (Informasi)
- Reverse engineering untuk interoperabilitas, penelitian keamanan, atau tujuan pendidikan sering dilindungi oleh undang-undang seperti DMCA Section 1201(f) di AS (bergantung yurisdiksi).
- Menganalisis aplikasi milik Anda sendiri atau aplikasi yang Anda miliki izin tertulis untuk menguji selalu legal.
- Mengakali proteksi untuk tujuan pembajakan umumnya ilegal di banyak yurisdiksi.
- Hormati kekayaan intelektual dan ketentuan layanan. Pengetahuan ini adalah alat; penerapannya membawa konsekuensi hukum dan etika.

---