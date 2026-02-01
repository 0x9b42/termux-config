---
chore: refine markdown formatting for notes/premium.md

Contents:
# Metodologi Lengkap Aktivasi Fitur Premium & Bypass In-App Purchase di Aplikasi Android

> CATATAN: Informasi ini hanya untuk security testing resmi, riset edukasi, dan analisis aplikasi yang Anda miliki sendiri atau yang Anda punya hak legal untuk menguji. Nge-bypass sistem pembayaran tanpa izin adalah ilegal dan melanggar ToS layanan. Gunakan hanya untuk tujuan yang etis dan legal.

## 1. Gambaran Arsitektur Sistem Pembayaran Android

Cara-cara umum untuk aktivasi fitur premium:

- Validasi lisensi lokal: logika di dalam aplikasi/device memeriksa status lisensi yang disimpan secara lokal.
- Validasi server remote: aplikasi meminta verifikasi pembelian ke server eksternal (license server atau API backend).
- In-App Billing (Google Play Billing Library): integrasi langsung ke API resmi Google Play.
- SDK pembayaran pihak ketiga: seperti PayPal, Stripe, dsb.

## 2. Metodologi Reverse Engineering Sistematis

### Fase 1 — Reconnaissance & Identifikasi

- Decompile APK menggunakan JADX.
- Cari kata kunci penting:
  - Terkait purchase/premium: `premium`, `pro`, `unlock`, `license`, `purchase`, `subscribe`, `upgrade`, `billing`, `paid`, `checkout`, `order`, `transaction`.
  - Google Play Billing: `com.android.billingclient`, `BillingClient`, `PurchasesUpdatedListener`, `SkuDetails`, package AIDL `com.android.vending.billing`.
  - Validasi: `isPurchased`, `isPremium`, `validateLicense`, `verifyPurchase`, `checkSubscription`, `entitlement`, `status`.
  - Flag boolean: `isPro`, `isPremiumUser`, `mUnlocked`.
  - Pihak ketiga: `paypal`, `stripe`, `razorpay`.
- Periksa `AndroidManifest.xml`:
  - Permissions seperti `com.android.vending.BILLING`.
  - Service/Receiver yang berkaitan dengan billing.
- Analisis traffic jaringan (awal):
  - Jalankan aplikasi lewat `mitmproxy` atau Burp Suite.
  - Cari endpoint verifikasi lisensi atau verifikasi receipt (biasanya ke Google atau server aplikasi sendiri).
  - Perhatikan pola request/response (mis. `{ "is_valid": true }`).

### Fase 2 — Analisis Statis: Menemukan Logika Validasi

- Trace dari entry point UI:
  - Cari ID tombol seperti `R.id.btn_upgrade`.
  - Ikuti alur pemanggilan method sampai masuk ke flow pembelian.
- Identifikasi fungsi validasi utama:
  - Umumnya ada method yang mengembalikan boolean untuk menentukan status premium — contoh: `public boolean isUserPremium()`.
  - Tujuan: temukan di mana nilai return method ini ditentukan.
- Analisis logika validasi:
  - Lokal: dapat membaca dari `SharedPreferences`, database lokal, atau file terenkripsi. Cari key seperti `premium_status`, `license_key`.
  - Remote: melibatkan network call. Cari class yang menangani API call dan parsing response (mis. `verifyPurchaseOnServer(String receipt)`).
  - Google Play Billing: aplikasi menggunakan `BillingClient` dan biasanya ada listener seperti `PurchasesUpdatedListener` atau pemanggilan `queryPurchases()`.

### Fase 3 — Analisis Dinamis & Hooking (FRIDA)

Di fase ini, aktivasi diuji dan diverifikasi. Tool andalan: Frida.

- Boolean flip sederhana (contoh):

```javascript
Java.perform(function() {
  var LicenseManager = Java.use('com.example.app.license.LicenseManager');
  LicenseManager.isUserPremium.implementation = function() {
    console.log('[+] isUserPremium() di-hook. Mengembalikan TRUE.');
    return true;
  };
});
```

- Bypass cek Google Play Billing — hook `queryPurchasesAsync` atau parser response:

```javascript
Java.perform(function() {
  var PurchaseClass = Java.use('com.android.billingclient.api.Purchase');
  var BillingHelper = Java.use('com.example.app.billing.BillingHelper');
  BillingHelper.getPurchasesList.implementation = function() {
    var realList = this.getPurchasesList();
    console.log('[+] Injeksi pembelian palsu.');
    // Buat object Purchase palsu atau kembalikan list yang tidak kosong
    return realList;
  };
});
```

- Bypass validasi server:
  - Cara A — hook response jaringan dan paksa respon sukses (contoh untuk native parsing):

```js
Interceptor.attach(Module.findExportByName('libnative.so', 'json_parse_verify_function'), {
  onLeave: function(retval) {
    // retval adalah pointer ke hasil verifikasi (misal 0=false, 1=true)
    // Overwrite memory-nya jadi 1 (true)
    retval.writeInt(1);
  }
});
```

  - Cara B — hook method yang mengevaluasi response server:

```javascript
Java.perform(function() {
  var ServerVerifier = Java.use('com.example.app.license.ServerVerifier');
  ServerVerifier.validateResponse.implementation = function(json) {
    console.log('[+] Validasi server di-hijack. Mengembalikan valid.');
    var ValidationResult = Java.use('com.example.app.license.ValidationResult');
    return ValidationResult.VALID.clone();
  };
});
```

- Bypass pembacaan file lisensi / SharedPreferences:

```javascript
Java.use('android.content.SharedPreferences').getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
  if (key.indexOf('license') !== -1 || key.indexOf('premium') !== -1) {
    console.log('[+] Intercept baca key: ' + key);
    return 'ACTIVATED_PRO_VERSION_12345'; // kembalikan string lisensi valid
  }
  return this.getString(key, defValue);
};
```

### Fase 4 — Patching & Aktivasi Permanen

Hook dinamis bersifat sementara. Untuk aktivasi permanen, lakukan patch pada APK.

- Decompile ke Smali dengan `apktool d`.
- Cari instruksi krusial (mis. `isUserPremium()`), analisis Smali.
- Teknik patching Smali umum:
  - Paksa return true (contoh Smali):

```smali
# Aslinya:
const/4 v0, 0x0  # false
return v0

# Patch menjadi:
const/4 v0, 0x1  # true
return v0
```

  - Bypass conditional jump: ubah kondisi `if-eqz` menjadi `if-nez` atau gunakan `goto :cond_success`.
  - NOP-in call ke validasi server: ganti `invoke-...` yang memanggil verifikasi jaringan dengan `nop`.

- Patching native library (`.so`):
  - Gunakan Ghidra/IDA untuk analisis.
  - Cari assembly check (mis. `CMP R0, #0` / `BEQ fail_label`) dan patch branch atau pembanding.
  - Ganti `.so` yang dimodifikasi ke folder `lib/` dalam APK.

- Repackaging & signing:
  - `apktool b` untuk rebuild.
  - Sign menggunakan `uber-apk-signer` atau metode signing lain.
  - Install: `adb install -r signed-modified.apk`.

### Fase 5 — Bypass Proteksi Lanjutan

- Verifikasi signature (integritas APK): aplikasi dapat mengecek signature. Hook `PackageManager.getPackageInfo` atau patch pengecekan signature di Smali.
- Deteksi emulator/root: matikan deteksi agar aplikasi hasil patch dapat berjalan; gunakan Frida atau patch method deteksi.
- Obfuscation (ProGuard/DexGuard): fokus pada perilaku dan string yang tersisa. Gunakan Frida tracing untuk mapping method yang diobfuscate.
- Re-validasi berkala: beberapa aplikasi melakukan pengecekan ulang lisensi secara periodik. Patch juga background service atau scheduler (`AlarmManager`, `WorkManager`).

## 3. Skenario Spesifik & Solusinya

| Skenario | Target Utama | Strategi Patching / Hooking |
|---|---:|---|
| Flag "Pro" lokal | Key di `SharedPreferences` atau field boolean | Hook getter atau set nilai langsung via Frida / Smali |
| License key offline | Algoritma validasi key | Trace algoritma, ambil master key, atau patch agar menerima key apa saja |
| Google Play Billing (online) | Hasil `queryPurchases()` | Hook sehingga mengembalikan objek `Purchase` palsu dengan `sku` yang benar; alternatifnya patch logika aplikasi yang memeriksa list kosong |
| Validasi receipt server remote | Parser response API server | Hook library jaringan untuk mengubah JSON response (`{"status":"valid"}`) atau hook method parser-nya |
| Cek langganan | Method `isEntitled()` yang memeriksa waktu kedaluwarsa | Hook agar selalu return `true`, atau patch perbandingan waktu kedaluwarsa |

## 4. Deteksi & Mitigasi Risiko untuk Developer

Pahami teknik di atas agar dapat memperkuat pertahanan aplikasi:

- Deteksi root/emulator: penting, tetapi tidak 100% aman.
- Obfuscation kode: gunakan DexGuard untuk enkripsi string dan proteksi anti-tampering.
- Anti-tampering: cek integritas kode, native library, dan signature di banyak titik yang tidak mudah ditebak.
- Server-side authority: solusi paling efektif adalah pindahkan logika fitur premium ke server. Aplikasi hanya sebagai client yang meminta akses setelah token pembelian divalidasi di sisi server.
- Native code terenkripsi/diobfuscate: implementasikan cek lisensi di C++ dengan anti-debugging.
- Analisis perilaku: deteksi pola tidak wajar (mis. fitur premium aktif namun tidak ada panggilan jaringan ke server verifikasi).

## 5. Batasan Legal & Etis

- Tujuan edukasi: mengoprek aplikasi sendiri untuk belajar biasanya diperbolehkan di banyak yurisdiksi.
- Security research: melaporkan bug secara bertanggung jawab sering dilindungi.
- Distribusi "APK crack": ilegal dan melanggar hak cipta.
- Mengakses layanan tanpa membayar: melanggar ToS dan bisa dianggap pencurian layanan.
- Selalu minta izin tertulis sebelum menguji aplikasi yang bukan milik Anda.

---

End of file.