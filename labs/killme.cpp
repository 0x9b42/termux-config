#include <jni.h>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <android/log.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

#define LOCAL_FILE_HEADER "PK\x03\x04"  // Signature untuk Local File Header
//#define LOG_TAG "SyscallNative"
//#define // LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
//#define // LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)



const char *ALLOWED_LIB = "libkillme.so";
std::string base64_chars;
const char *hash = "348f20edda990941a97893ca9423fbc1333790037a8ba4b023a2546578b16f4d";

const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Fungsi bantu untuk rotasi bit
uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// Implementasi SHA-256
std::string o000o0o00o0o000o0o0(const std::string &data) {
    uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    std::vector<uint8_t> padded(data.begin(), data.end());
    padded.push_back(0x80);
    while ((padded.size() + 8) % 64 != 0)
        padded.push_back(0x00);

    uint64_t bit_len = data.size() * 8;
    for (int i = 7; i >= 0; i--)
        padded.push_back((bit_len >> (i * 8)) & 0xFF);

    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32_t w[64] = {0};
        for (size_t j = 0; j < 16; j++)
            w[j] = (padded[i + j * 4] << 24) | (padded[i + j * 4 + 1] << 16) |
                   (padded[i + j * 4 + 2] << 8) | (padded[i + j * 4 + 3]);

        for (size_t j = 16; j < 64; j++)
            w[j] = gamma1(w[j - 2]) + w[j - 7] + gamma0(w[j - 15]) + w[j - 16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_temp = h[7];

        for (size_t j = 0; j < 64; j++) {
            uint32_t temp1 = h_temp + sigma1(e) + ch(e, f, g) + k[j] + w[j];
            uint32_t temp2 = sigma0(a) + maj(a, b, c);
            h_temp = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_temp;
    }

    std::stringstream ss;
    for (uint32_t val : h)
        ss << std::hex << std::setw(8) << std::setfill('0') << val;
    return ss.str();
}

char o000o0o00o0o000o0o000o0o(int index) {
    if (index < 0 || index >= 64) {
        return '\0';
    }
    return base64_chars[index];
}


// 📌 Force Close
void o000o0o00o0o000o0o000o00oo00() {
    // LOGE("❌ Deteksi manipulasi! Memaksa aplikasi FC...");

    // 🔴 Segmentation Fault
    int *p = NULL;
    *p = 42;

    // 🔴 Syscall kill()
    syscall(SYS_kill, getpid(), SIGKILL);

    // 🔴 Syscall exit()
    syscall(SYS_exit, 1);

    // 🔴 Overwrite memori
    memset((void *) o000o0o00o0o000o0o000o00oo00, 0xFF, 1024);

    // 🔴 Infinite Loop
    while (true) {}
}


// 📌 Cek apakah "assets/" ada dalam APK sebagai entri ZIP
std::string o000o0o00o0o000o0o000o00o0(const char *apk_path, const char *signature_str) {
    o000o0o00o0o000o0o000o00oo00();
    std::string x;
    if(o000o0o00o0o000o0o0(signature_str) != hash){
        o000o0o00o0o000o0o000o00oo00();
        return std::string() + o000o0o00o0o000o0o000o0o(2) + o000o0o00o0o000o0o000o0o(8) + o000o0o00o0o000o0o000o0o(9) +
               o000o0o00o0o000o0o000o0o(29) + o000o0o00o0o000o0o000o0o(30);
    }
    x = x + o000o0o00o0o000o0o000o0o(10 + 7);
    int fd = syscall(SYS_openat, AT_FDCWD, apk_path, O_RDONLY);
    if (fd < 0) {
        // LOGE("❌ Gagal membuka APK file: %s", apk_path);
        o000o0o00o0o000o0o000o00oo00();
    }
    x = x + o000o0o00o0o000o0o000o0o(6 * 6);

    off_t file_size = lseek(fd, 0, SEEK_END);

    x = x + o000o0o00o0o000o0o000o0o(7 * 7);
    if (file_size < 0) {
        // LOGE("❌ Gagal mendapatkan ukuran file APK");
        syscall(SYS_close, fd);
        o000o0o00o0o000o0o000o00oo00();
    }

    x = x + o000o0o00o0o000o0o000o0o(23 / 23);
    lseek(fd, 0, SEEK_SET);
    x = x + o000o0o00o0o000o0o000o0o(15 + 2);
    void *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    x = x + o000o0o00o0o000o0o000o0o(10 * 5 + 5);
    syscall(SYS_close, fd);
    x = x + o000o0o00o0o000o0o000o0o(35 + 10);

    if (map == MAP_FAILED) {
        // LOGE("❌ mmap gagal pada APK");
        o000o0o00o0o000o0o000o00oo00();
    }

    x = x + o000o0o00o0o000o0o000o0o(30 - 10);
    const char *data = (const char *)map;
    x = x + o000o0o00o0o000o0o000o0o(4 * 4 - 4);
    int found_assets = 0;
    x = x + o000o0o00o0o000o0o000o0o(1 + 2);
    int found_lib_other = 0;
    x = x + o000o0o00o0o000o0o000o0o(1);

    for (off_t i = 0; i < file_size - 8; i++) {
        // 📂 Deteksi "assets/"
        if (memcmp(data + i, "PK\x03\x04", 4) == 0 || memcmp(data + i, "PK\x01\x02", 4) == 0) {
            if (memcmp(data + i + 30, "assets/", 7) == 0) {
                // LOGI("📂 Ditemukan folder atau file di assets/ pada offset %ld", i);
                found_assets = 1;
                o000o0o00o0o000o0o000o00oo00();
                base64_chars = "";
            }
        }

        // 🏗️ Deteksi "lib/" dengan library selain libkillme.so
        if (memcmp(data + i, "PK\x03\x04", 4) == 0 && memcmp(data + i + 30, "lib/", 4) == 0) {
            const char *lib_path = data + i + 30;
            if (strstr(lib_path, ALLOWED_LIB) == NULL) {
                // LOGE("🚨 Library mencurigakan terdeteksi: %s", lib_path);
                found_lib_other = 1;
                o000o0o00o0o000o0o000o00oo00();
                base64_chars = "";
                break;
            }
        }
    }
    x = x + o000o0o00o0o000o0o000o0o(3 * 10 + 1);

    if (found_assets) {
        // LOGE("❌ Folder assets/ ditemukan! Memicu crash...");
        o000o0o00o0o000o0o000o00oo00();
        base64_chars = "";
    }

    x = x + o000o0o00o0o000o0o000o0o(5 + 5 + 5 + 5 - 3);
    if (found_lib_other) {
        // LOGE("❌ Library tidak dikenal ditemukan! Memicu crash...");
        o000o0o00o0o000o0o000o00oo00();
        base64_chars = "";
    }
    o000o0o00o0o000o0o000o00oo00();
    x = x + o000o0o00o0o000o0o000o0o(20 - (20 / 20));
    munmap(map, file_size);
    x = x + o000o0o00o0o000o0o000o0o(20 - 3);
    return x;
}

std::string getFlag(const char *apk_path, const char *signature){
    base64_chars+= "0123456789+/";
    std::string x = std::string() + o000o0o00o0o000o0o000o0o(5 * 5 - 6);
    std::string y = o000o0o00o0o000o0o000o00o0(apk_path, signature) + x +
                    o000o0o00o0o000o0o000o0o(20 + 10 - 10 + 2);
    return y + o000o0o00o0o000o0o000o0o(20 + 1);
}

// 📌 JNI_OnLoad
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    // LOGI("✅ JNI_OnLoad dipanggil, menunggu path dari Java...");
    return JNI_VERSION_1_6;
}

int oo0o0ooo000o0o0o0oo0(const char *apk_path) {
    int fd = open(apk_path, O_RDONLY);
    if (fd < 0) {
        // LOGE("❌ Gagal membuka APK: %s\n", apk_path);
        o000o0o00o0o000o0o000o00oo00();
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        // LOGE("❌ Gagal mendapatkan ukuran APK\n");
        close(fd);
        o000o0o00o0o000o0o000o00oo00();
        return -1;
    }

    size_t size = st.st_size;
    char *data = (char *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        // LOGE("❌ mmap() gagal\n");
        close(fd);
        o000o0o00o0o000o0o000o00oo00();
        return -1;
    }
    base64_chars = "ABCDE";

    int count = 0;
    char *ptr = data;
    char *end = data + size;

    // Cari semua header "PK\x03\x04"
    while ((ptr = (char *)memmem(ptr, end - ptr, LOCAL_FILE_HEADER, 4))) {
        if(count > 1){
            o000o0o00o0o000o0o000o00oo00();
        }
        ptr += 26;  // Lompat ke bagian filename length
        if (ptr + 4 > end) break; // Pastikan tidak melewati batas memori

        uint16_t filename_length = *(uint16_t *)ptr;
        ptr += 2;   // Lompat ke extra length
        uint16_t extra_length = *(uint16_t *)ptr;
        ptr += 2;   // Lompat ke bagian filename

        if (ptr + filename_length > end) break; // Hindari buffer overflow

        std::string filename(ptr, filename_length); // Simpan nama file
        ptr += filename_length + extra_length; // Lompat ke data berikutnya

        if (filename.rfind("classes", 0) == 0 && filename.find(".dex") != std::string::npos) {
            count++;
            base64_chars+= "FGH";
            // LOGI("📦 Ditemukan: %s\n", filename.c_str());
        }
    }

    base64_chars += "IJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    munmap(data, size);
    close(fd);
    return count;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_killme_MainActivity_getFlag(JNIEnv *env, jclass clazz, jstring apkPath, jstring signature) {
    // Ambil string dari jstring
    const char *apk_path = env->GetStringUTFChars(apkPath, NULL);
    if (apk_path == NULL) {
        // LOGE("❌ JNI Error: APK Path NULL");
        return env->NewStringUTF("");
    }

    const char *signature_str = env->GetStringUTFChars(signature, NULL);
    if (signature_str == NULL) {
        // LOGE("❌ JNI Error: Signature NULL");
        env->ReleaseStringUTFChars(apkPath, apk_path); // ✅ Pastikan apk_path tetap direlease
        return env->NewStringUTF("");
    }
//    std::string input = "HBrgK8adsbyjnkYhWkCqYsUvYh2W2WcHZwbM6yHUR0E=";
//    std::string hash = o000o0o00o0o000o0o0(signature_str);

    int count = oo0o0ooo000o0o0o0oo0(apk_path);
    // LOGI("✅ APK Path dari Java: %s", apk_path);
    // LOGI("✅ Signature dari Java: %s", hash.c_str());
    // LOGI("✅ Dex count: %d", count);
    // Dapatkan flag
    const std::string flag = getFlag(apk_path, signature_str);

    //std::string flag = "flag";
    // Bebaskan string JNI setelah selesai digunakan
    env->ReleaseStringUTFChars(apkPath, apk_path);
    env->ReleaseStringUTFChars(signature, signature_str); // ✅ Bebaskan signature_str juga

    return env->NewStringUTF(flag.c_str());
}
