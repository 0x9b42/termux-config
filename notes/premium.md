Metodologi Lengkap Aktivasi Fitur Premium & Bypass In-App Purchase di Aplikasi Android
> CATATAN: Informasi ini bener-bener cuma buat security testing resmi, riset edukasi, dan analisis aplikasi yang emang lu punya sendiri atau lu punya hak legal buat ngopreknya. Nge-bypass sistem pembayaran tanpa izin itu ilegal dan melanggar ToS.
> 
1. GAMBARAN ARSITEKTUR SISTEM PEMBAYARAN ANDROID
Cara-cara umum buat aktivasi fitur premium:
 * Validasi Lisensi Lokal: Logika di dalem aplikasi/device ngecek status lisensi yang disimpen di situ.
 * Validasi Server Remote: Aplikasi nanya ke server luar (license server atau API backend) buat verifikasi pembelian.
 * In-App Billing Service (Google Play Billing Library): Integrasi langsung sama API resmi Google Play.
 * SDK Pembayaran Pihak Ketiga: Kayak PayPal, Stripe, dsb.
2. METODOLOGI REVERSE ENGINEERING SISTEMATIS
FASE 1: RECONNAISSANCE & IDENTIFIKASI
 * Decompile APK pake JADX.
 * Cari Keyword Penting:
   * Terkait Purchase/Premium: premium, pro, unlock, license, purchase, subscribe, upgrade, billing, paid, checkout, order, transaction.
   * Google Play Billing: com.android.billingclient, BillingClient, purchaseUpdatedListener, SkuDetails, nama package AIDL (com.android.vending.billing).
   * Validasi: isPurchased, isPremium, validateLicense, verifyPurchase, checkSubscription, entitlement, status.
   * Flag Boolean: isPro, isPremiumUser, mUnlocked.
   * Pihak Ketiga: paypal, stripe, razorpay.
 * Cek AndroidManifest.xml:
   * Izin (Permissions): com.android.vending.BILLING.
   * Service/Receiver yang ada hubungannya sama billing.
 * Analisis Traffic Jaringan (Awal):
   * Jalanin aplikasi lewat mitmproxy atau Burp Suite.
   * Cari endpoint buat verifikasi lisensi atau validasi receipt pembelian (biasanya ke Google atau server si aplikasi sendiri).
   * Perhatiin pola request/response (misalnya: {"is_valid":true}).
FASE 2: ANALISIS STATIS - NYARI LOGIKA VALIDASI
 * Trace dari Entry Point:
   * Cari ID tombol "Upgrade to Pro" (search ID onClick kayak R.id.btn_upgrade).
   * Ikutin alur method call-nya sampe masuk ke flow pembelian.
 * Identifikasi Fungsi Validasi Utama:
   * Biasanya ada satu method yang balikin nilai boolean buat nentuin status premium.
   * Contoh: public boolean isUserPremium() { ... }.
   * Goal-nya: Cari di mana nilai return method ini ditentuin.
 * Analisis Logika Validasi:
   * Cek Lokal: Mungkin baca dari SharedPreferences, database lokal, atau file terenkripsi. Cari nama key kayak premium_status, license_key.
   * Cek Remote: Melibatkan network call. Cari class yang handle API call dan parsing response-nya. Biasanya ada method kayak verifyPurchaseOnServer(String receipt).
   * Google Play Billing: Aplikasi bakal pake BillingClient buat query pembelian. Cek krusialnya biasanya ada di PurchasesUpdatedListener atau setelah manggil queryPurchases().
FASE 3: ANALISIS DINAMIS & HOOKING
Di fase ini, aktivasinya dites dan diverifikasi. Tool andalannya: FRIDA.
 * Boolean Flip Sederhana:
   Kalo lu nemu isUserPremium() atau sejenisnya, bikin script Frida buat maksa return-nya jadi true.
   Java.perform(function() {
    var TargetClass = Java.use('com.example.app.license.LicenseManager');
    TargetClass.isUserPremium.implementation = function() {
        console.log("[+] isUserPremium() di-hook. Balikin TRUE.");
        return true;
    };
});

 * Bypass Cek Google Play Billing:
   Hook method queryPurchasesAsync di BillingClient atau parser response-nya.
   // Contoh: Hook method internal yang proses list pembelian
Java.perform(function() {
    var PurchaseClass = Java.use('com.android.billingclient.api.Purchase');
    var SomeClass = Java.use('com.example.app.billing.BillingHelper');
    SomeClass.getPurchasesList.implementation = function() {
        var realList = this.getPurchasesList();
        console.log("[+] Injeksi pembelian palsu.");
        // Bikin object purchase palsu atau balikin list yang nggak kosong
        return realList;
    };
});

 * Bypass Validasi Server:
   * Cara A: Hook response jaringan. Paksa response-nya supaya nunjukin sukses.
     // Kalo pake OkHttp atau Retrofit
Interceptor.attach(Module.findExportByName("libnative.so", "json_parse_verify_function"), {
    onLeave: function(retval) {
        // retval itu pointer ke hasil verifikasi (misal 0=false, 1=true)
        // Overwrite memory-nya jadi 1 (true)
        retval.writeInt(1);
    }
});

   * Cara B: Hook method yang evaluasi response server.
     Java.use('com.example.app.license.ServerVerifier').validateResponse.implementation = function(json) {
    console.log("[+] Validasi server di-hijack. Balikin valid.");
    return Java.use('com.example.app.license.ValidationResult').VALID.clone();
};

 * Bypass File Lisensi Lokal/SharedPreferences:
   Hook bagian pembacaan file atau getter SharedPreferences.
   Java.use('android.content.SharedPreferences').getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
    if (key.indexOf("license") !== -1 || key.indexOf("premium") !== -1) {
        console.log("[+] Intercept baca key: " + key);
        return "ACTIVATED_PRO_VERSION_12345"; // Balikin string lisensi valid
    }
    return this.getString(key, defValue);
};

FASE 4: PATCHING & AKTIVASI PERMANEN
Hook dinamis itu cuma sementara. Buat "crack" permanen, lu harus nge-patch APK-nya.
 * Cari Instruksi Krusial di Smali:
   * Pake apktool d buat decompile ke Smali.
   * Cari method krusialnya (misal isUserPremium()).
   * Analisis kode Smali-nya. Kuncinya biasanya ada di conditional jump atau nilai return.
 * Teknik Patching Smali yang Umum:
   * Paksa Return True:
     Aslinya:
     const/4 v0, 0x0  # Isi register v0 dengan false (0)
return v0        # Balikin false

     Patch jadi:
     const/4 v0, 0x1  # Isi register v0 dengan true (1)
return v0        # Balikin true

   * Bypass Conditional Jump:
     Biasanya ada cek if-eqz v0, :cond_0 (lompat ke gagal kalo v0 itu nol). Ubah jadi if-nez v0, :cond_0 atau pake goto :cond_success (langsung lompat ke blok sukses tanpa syarat).
   * NOP-in Call ke Validasi Server:
     Cari invoke-static atau invoke-virtual yang manggil method verifikasi jaringan, terus ganti sama instruksi nop.
 * Patching Native Library (.so):
   * Kalo validasinya di kode native, pake Ghidra atau IDA.
   * Cari assembly check-nya (contoh: CMP R0, #0 / BEQ fail_label).
   * Patch binary-nya: Ganti BEQ (Branch if Equal) jadi BNE (Branch if Not Equal), atau ubah nilai pembandingnya.
   * Save .so yang udah dimodif terus balikin lagi ke folder lib/ di dalem APK.
 * Repackaging & Signing:
   * apktool b buat rebuild.
   * Sign pake uber-apk-signer.
   * Install: adb install -r signed-modified.apk.
FASE 5: NGE-BYPASS PROTEKSI LANJUTAN
 * Verifikasi Signature (Integritas APK):
   Aplikasi mungkin ngecek signature APK-nya sendiri. Hook PackageManager.getPackageInfo terus modif field signatures-nya, atau patch method pengecekannya di Smali.
 * Deteksi Emulator/Root:
   Ini harus dimatiin supaya aplikasi hasil patch bisa jalan. Pake hook Frida atau patch method deteksinya kayak cara di atas.
 * Obfuscation (ProGuard/DexGuard):
   * Nama class/method bakal diubah jadi aneh (misal a.a(), b.c()).
   * Strategi: Fokus ke perilaku (behavior) dan referensi string. Cari string yang masih sisa kayak purchase, billing, atau pesan error.
   * Pake Frida tracing buat mapping method yang diobfuscate.
 * Re-validasi Berkala:
   Beberapa aplikasi ngecek lisensi ulang secara periodik. Lu mungkin perlu patch background service atau scheduler juga (cari AlarmManager, WorkManager, dsb).
3. SKENARIO SPESIFIK & SOLUSINYA

| Skenario | Target Utama | Strategi Patching/Hooking |
|---|---|---|
| Flag "Pro" Lokal | Key SharedPreferences atau field boolean. | Hook getter-nya atau set langsung nilainya via Frida/Smali. |
| License Key Offline | Algoritma validasi key. | Trace algoritmanya, ambil master key-nya, atau patch supaya nerima key apa aja. |
| Google Play Billing (Online) | List hasil queryPurchases(). | Hook supaya balikin object Purchase palsu dengan sku yang bener. Lebih gampang patch logika aplikasi yang ngecek apakah list-nya kosong. |
| Validasi Receipt Server Remote | Parser response API server. | Hook library jaringan buat modif JSON response ({"status":"valid"}), atau hook method parser-nya. |
| Cek Langganan | Method isEntitled() dengan cek waktu expired. | Hook supaya selalu return true, atau patch perbandingan waktu expired-nya. |
4. DETEKSI & MITIGASI RISIKO BUAT DEVELOPER
Paham cara kerjanya penting banget buat pertahanan.
 * Deteksi Root/Emulator: Penting, tapi nggak 100% aman.
 * Obfuscation Kode: Pake DexGuard buat enkripsi string dan proteksi anti-tampering.
 * Anti-Tampering: Cek integritas kode, native library, dan signature di banyak titik yang nggak ketebak.
 * Server-Side Authority: Ini solusi paling ampuh. Pindahin logika fitur premium ke server. Aplikasi cuma jadi client yang minta akses setelah token pembelian divalidasi di sisi server.
 * Native Code yang Diobfuscate: Implementasi cek lisensi di C++ dengan anti-debugging.
 * Analisis Perilaku: Deteksi pola nggak wajar (misal fitur premium aktif tapi nggak ada network call ke server Google).
5. BATASAN LEGAL & ETIS
 * Tujuan Edukasi: Ngoprek aplikasi sendiri buat belajar itu biasanya boleh (fair use) di banyak negara.
 * Security Research: Ngelaporin bug secara bertanggung jawab itu dilindungi.
 * Distribusi "APK Crack": Ilegal, melanggar hak cipta.
 * Dapet Akses Layanan Tanpa Bayar: Melanggar ToS dan bisa dianggap pencurian layanan.
 * Selalu minta izin tertulis sebelum ngetes aplikasi yang bukan punya lu sendiri.
