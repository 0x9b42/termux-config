# Metodologi Analisis Statis untuk Modifikasi In-App Purchase (Status VIP/Premium) pada Aplikasi Android Terobfuskasi

**DISCLAIMER HUKUM (Hanya formalitas, sesuai protokol):**  
Tutorial ini murni untuk tujuan penelitian keamanan, audit kode, atau pengujian penetrasi pada aplikasi milik sendiri. Pelanggaran hak kekayaan intelektual merupakan tindakan kriminal.

---

## Daftar Isi
- Bagian 1 — Lingkungan dan Alat (Toolchain)  
- Bagian 2 — Metodologi Analisis Statis Sistematis  
  - Langkah 1: Dekompilasi dan Survei Awal  
  - Langkah 2: Analisis Manifest dan Resource  
  - Langkah 3: Pelacakan Alur Pembelian dan Validasi (Inti)  
  - Langkah 4: Strategi Modifikasi (Patching)  
  - Langkah 5: Rekompilasi dan Penandatanganan  
- Bagian 3 — Teknik Khusus untuk Kode Terobfuskasi ProGuard  
- Bagian 4 — Validasi dan Pengujian  
- Kesimpulan dan Best Practice

---

## BAGIAN 1 — LINGKUNGAN DAN ALAT (TOOLCHAIN)

1. Reverse Engineering Suite
   - Apktool  
     - Contoh: `apktool d target.apk` — dekompilasi APK ke resource, manifest, dan classes.dex.
   - dex2jar / d2j-dex2jar  
     - Konversi `classes.dex` ke `classes-dex2jar.jar`.
   - JD-GUI / FernFlower / CFR  
     - Decompiler Java dari file .jar untuk mendapatkan source `.java`. FernFlower (terintegrasi dalam Jadx) sering bagus untuk kode terobfuskasi.

2. Analisis Statis Utama
   - Jadx (Wajib)  
     - Contoh: `jadx-gui target.apk` — tool all-in-one dengan deobfuscator ProGuard terintegrasi; fitur cross-reference sangat berguna.

3. Analisis Kode Lanjutan
   - Bytecode Viewer — menggabungkan kemampuan Apktool, CFR, FernFlower, dan memungkinkan editing bytecode langsung.
   - Android Studio (atau IDE lain) + Java Decompiler Plugin — untuk navigasi dan analisis kode dekompilasi.

4. Analisis Resource & Native
   - Jadx — cukup untuk resource.
   - IDA Pro / Ghidra — jika ada komponen native (`lib/*.so`) untuk proteksi tambahan.

5. Patching & Rekompilasi
   - Apktool untuk rekompilasi: `apktool b target_dir -o modified.apk`.
   - Uber APK Signer: untuk menandatangani ulang APK.
   - Frida (opsional): untuk analisis dinamis guna memvalidasi temuan statis.

---

## BAGIAN 2 — METODOLOGI ANALISIS STATIS SISTEMATIS

**Prinsip utama:** temukan titik di mana status pengguna (premium/VIP) diverifikasi — biasanya setelah purchase sukses. Fokus pada boolean/flag yang mengontrol akses fitur premium.

### LANGKAH 1 — DEKOMPILASI DAN SURVEI AWAL
Contoh perintah:
```bash
apktool d target.apk -o target_dir
jadx-gui target.apk
```

- Buka Jadx dan periksa "ProGuard Map" jika tersedia.
- Cari package/class yang berkaitan dengan purchase/billing. Keyword yang berguna:
  - `purchase`, `billing`, `inapp`, `iap`, `subscription`
  - `premium`, `vip`, `pro`, `unlock`, `license`, `upgrade`
  - `verify`, `validation`, `check`, `status`
  - `sku`, `productId`
  - `com.android.billingclient.api` (Google Play Billing Library)

### LANGKAH 2 — ANALISIS MANIFEST DAN RESOURCE
- Di Jadx, buka `AndroidManifest.xml`. Cari permission `com.android.vending.BILLING`.
- Periksa `res/values/strings.xml` dan `res/values/public.xml` untuk string terkait produk (`sku_premium_monthly`, `title_vip`, dll). Catat ID produk.

### LANGKAH 3 — PELACAKAN ALUR PEMBELIAN DAN VALIDASI (INTI)
1. Titik awal: Activity atau Fragment pembelian.
   - Cari class yang mengimplementasi `PurchasesUpdatedListener` atau `BillingClientStateListener`.
   - Nama class bisa terobfuskasi (mis. `a.a.a.c`).

2. Analisis callback/listener pembelian:
   - Perhatikan `onPurchasesUpdated(BillingResult billingResult, List<Purchase> purchases)` dan alur setelah pembelian sukses.
   - Biasanya kode mengirim token pembelian ke server atau verifikasi lokal.

3. Identifikasi metode verifikasi status premium/VIP (target utama):
   - Cari signature-metode umum:
     ```java
     public boolean isPremium()
     public boolean isVIP()
     public boolean isPro()
     public boolean isSubscribed()
     public int getUserStatus() // mis. return 1 untuk premium
     public boolean checkLicense()
     ```
   - Metode ini sering berada di Singleton/Manager (mis. `LicenseManager`, `PurchaseHelper`, `UserStatusManager`).
   - Gunakan fitur "Find Usage" / Cross-Reference (Xref) di Jadx untuk menemukan semua pemanggilan.

4. Reverse engineering logika verifikasi:
   - Buka body metode `isPremium()` dan analisis pola:
     - Pengecekan lokal: mis. `return sp.getBoolean("is_premium", false);`
     - Pengecekan server: panggilan network lalu parse JSON response (endpoint seperti `/verify_purchase` atau `/get_user_status`).
     - Cache hasil verifikasi: sering disimpan di `SharedPreferences` atau DB lokal.

### LANGKAH 4 — STRATEGI MODIFIKASI (PATCHING)
Asumsi target: metode `isPremium()` melakukan verifikasi lokal sederhana.

1. Lokalisasi file bytecode:
   - Dari Jadx temukan nama class lengkap (mis. `com.example.app.license.a`).
   - Temukan file `.smali` di folder hasil Apktool: `target_dir/smali/com/example/app/license/a.smali`.

2. Analisis dan modifikasi Smali:
   - Cari definisi method, mis. `.method public isPremium()Z`.
   - Contoh modifikasi sederhana (selalu mengembalikan `true`):

     Kode asli (contoh):
     ```smali
     .method public isPremium()Z
         .locals 1
         .line 123
         iget-boolean v0, p0, Lcom/example/app/license/a;->isPremium:Z
         return v0
     .end method
     ```

     Patch menjadi:
     ```smali
     .method public isPremium()Z
         .locals 1
         .line 123
         const/4 v0, 0x1  # true
         return v0
     .end method
     ```

3. Strategi untuk kasus lebih kompleks:
   - Jika verifikasi via server: cari bagian yang mem‑parse response server dan ubah logikanya agar selalu menganggap valid, atau bypass panggilan network.
   - Jika ada verifikasi signature: temukan `Security.verifyPurchase(signature, purchaseData)` dan ubah agar selalu return `true` (jika verifikasi lokal).
   - Jika ada multiple checks: temukan semua metode terkait (`isTrial()`, `isLicenseValid()`, `isPremium()`) dan patch semuanya.

### LANGKAH 5 — REKOMPILASI DAN PENANDATANGANAN
1. Rekompilasi:
```bash
apktool b target_dir -o modified.apk
```
2. Tandatangani APK:
```bash
java -jar uber-apk-signer.jar --apks modified.apk
```
3. Instal:
- Uninstall versi asli (jika perlu), lalu install APK hasil modifikasi di perangkat atau emulator.

---

## BAGIAN 3 — TEKNIK KHUSUS UNTUK KODE TEROBFUSKASI PROGUARD

1. String Decryption
   - ProGuard tidak mengenkripsi string, tetapi beberapa aplikasi menambah enkripsi manual.
   - Cari method yang sering dipanggil untuk dekripsi (mis. `a.a.a.a(String)`) dan analisa implementasinya di Jadx atau hook via Frida saat runtime untuk melihat output.

2. Identifier Renaming
   - Jadx mencoba mendeobfuscate, tapi nama sering menjadi `C0384a` dsb.
   - Gunakan pola dan konteks:
     - Perhatikan parameter/return type.
     - Amati string literal di dalam method (string biasanya tidak di-rename).
     - Mis. method yang mengandung `"Purchase verified"` dan return boolean kemungkinan besar adalah `verifyPurchase()`.

3. Control Flow Obfuscation
   - Logika bisa dipecah jadi banyak jump/switch; Jadx sering mampu menyederhanakan, bila tidak periksa smali langsung cari pola `if-eqz` / `if-nez`.

4. Library Obfuscation
   - Fokus ke kode aplikasi (package app) ketimbang library pihak ketiga (mis. Google Play Billing). Kode aplikasi biasanya mengandung string/behavior yang bisa diidentifikasi.

---

## BAGIAN 4 — VALIDASI DAN PENGUJIAN

1. Analisis Cross-Reference (Xref) Lengkap  
   - Pastikan semua jalur yang memanggil metode yang dipatch telah tertangani.

2. Debugging dengan Logging  
   - Tambahkan logging di smali (gunakan `invoke-static` ke `Log.d()` mis.) untuk memastikan metode yang dipatch memang dipanggil.

3. Dynamic Analysis dengan Frida (Opsional tapi efektif)  
   - Gunakan script Frida untuk mem-hook `isPremium()` sebelum melakukan patch statis. Contoh sederhana:
```javascript
Java.perform(function() {
    var targetClass = Java.use("com.example.app.license.a");
    targetClass.isPremium.implementation = function() {
        console.log("[+] isPremium() hooked, returning true");
        return true;
    };
});
```

---

## KESIMPULAN DAN BEST PRACTICE

- Metodologi ini bersifat iteratif: Identifikasi → Analisis → Patch → Validasi → Ulangi.  
- Keberhasilan sangat bergantung pada ketelitian dalam mengikuti alur kode, terutama pada aplikasi yang terobfuskasi.  
- Prioritaskan analisis metode verifikasi lokal sebelum menangani logika jaringan.  
- Selalu backup file asli sebelum memodifikasi.  
- Aplikasi enterprise dengan proteksi tambahan (root/emulator detection, integrity checks) memerlukan teknik lanjutan (hook native, patch .so, anti-debug bypass).  
- Toolchain dan metodologi ini memberikan fondasi; implementasi praktis memerlukan eksperimen dan penyesuaian terhadap proteksi spesifik target.
