Platinmods - Android & iOS Mods, MOD APK Mobile Games & Apps

 Thread starterKur0  Start dateApr 9, 2022
Kur0
Apr 9, 2022

It's been a while since I've posted things related to modding, now i'm back with something i used to worked on.
Maybe some of already heard of PMS Hook, Ultima, NP, etc. have you ever wondered how those tool can bypass APK signature/integrity check?
When an android application is loaded, there are various processes happening, including loading the APK Information.
So how does the "APK Information" stuff looks like? well here is one of the example of Java Internal class that contains APK Information.

LoadedApk:
Java:
```java
public final class LoadedApk {
    static final String TAG = "LoadedApk";
    static final boolean DEBUG = false;
    private static final String PROPERTY_NAME_APPEND_NATIVE = "pi.append_native_lib_paths";

    @UnsupportedAppUsage
    private final ActivityThread mActivityThread;
    @UnsupportedAppUsage
    final String mPackageName;
    @UnsupportedAppUsage
    private ApplicationInfo mApplicationInfo;
    @UnsupportedAppUsage
    private String mAppDir;
    @UnsupportedAppUsage
    private String mResDir;
    private String[] mOverlayDirs;
    @UnsupportedAppUsage
    private String mDataDir;
    @UnsupportedAppUsage
    private String mLibDir;
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    private File mDataDirFile;
    private File mDeviceProtectedDataDirFile;
    private File mCredentialProtectedDataDirFile;
    @UnsupportedAppUsage
    private final ClassLoader mBaseClassLoader;
    private ClassLoader mDefaultClassLoader;
    private final boolean mSecurityViolation;
    private final boolean mIncludeCode;
    private final boolean mRegisterPackage;
    @UnsupportedAppUsage
    private final DisplayAdjustments mDisplayAdjustments = new DisplayAdjustments();
    /** WARNING: This may change. Don't hold external references to it. */
    @UnsupportedAppUsage
    Resources mResources;
    @UnsupportedAppUsage
    private ClassLoader mClassLoader;
    @UnsupportedAppUsage
    private Application mApplication;

    private String[] mSplitNames;
    private String[] mSplitAppDirs;
    @UnsupportedAppUsage
    private String[] mSplitResDirs;
    private String[] mSplitClassLoaderNames;

    @UnsupportedAppUsage
    private final ArrayMap<Context, ArrayMap<BroadcastReceiver, ReceiverDispatcher>> mReceivers
        = new ArrayMap<>();
    private final ArrayMap<Context, ArrayMap<BroadcastReceiver, LoadedApk.ReceiverDispatcher>> mUnregisteredReceivers
        = new ArrayMap<>();
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    private final ArrayMap<Context, ArrayMap<ServiceConnection, LoadedApk.ServiceDispatcher>> mServices
        = new ArrayMap<>();
    private final ArrayMap<Context, ArrayMap<ServiceConnection, LoadedApk.ServiceDispatcher>> mUnboundServices
        = new ArrayMap<>();
    private AppComponentFactory mAppComponentFactory;

    Application getApplication() {
        return mApplication;
    }
};
```

As you can see that in the class above, there are various informations regarding to the APK, including Package Name, Application's Directory, and ApplicationInfo (We'll get through this later). In the application memory, this class is being stored to store/get information about the APK, however you can't get any of the class fields without using reflection.
So in return, android provides function like getPackageResourcePath & getPackageCodePath (returns .apk path), getApplicationInfo (returns current application information), developers can use those functions to grab the application information. In game security, those kind of stuff is very useful to detect stuff game tampering (modding), changed apk signatures, etc.

One of the example for a game to detect whether if current game is being tampered, is by checking the APK signature or APK integrity, how?
Game can use getPackageInfo to retrieve APK's signature and then checking whether if that signature match the original signature, game can also opens the .apk file and see if the .apk is actually being tampered by doing some checks like md5, crc, etc.

I've come up solution to bypass this stuff using Reflection.
What is Reflection? Reflection is a process of examining or modifying the run time behavior of a class at run time. The java. lang. Class class provides many methods that can be used to get metadata, examine and change the run time behavior of a class. So with this advantage, we can easily access the java internal classes and fields, modify those field so that game think if the apk is not being tampered by changing the apk path and signature to the original one.

Here's were APKKiller works in action, take a look the source code below:
C++:
```cpp
#include <stdio.h>
#include <iostream>
#include <string>
#include <jni.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "APKKiller", __VA_ARGS__)

#define apk_asset_path "original.apk"
#define apk_fake_name ".nino"
std::vector<std::vector<uint8_t>> apk_signatures {{0x30, 0x82, 0x03, 0x7D, 0x30, 0x82, 0x02, 0x65, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x1D, 0xCE, 0x86, 0xA4, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x6E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x38, 0x36, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x47, 0x75, 0x61, 0x6E, 0x67, 0x20, 0x44, 0x6F, 0x6E, 0x67, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x53, 0x68, 0x65, 0x6E, 0x20, 0x5A, 0x68, 0x65, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x54, 0x65, 0x6E, 0x63, 0x65, 0x6E, 0x74, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x07, 0x54, 0x65, 0x6E, 0x63, 0x65, 0x6E, 0x74, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x48, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x20, 0x4C, 0x75, 0x30, 0x20, 0x17, 0x0D, 0x31, 0x37, 0x31, 0x32, 0x32, 0x38, 0x31, 0x31, 0x33, 0x37, 0x30, 0x37, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x31, 0x37, 0x31, 0x32, 0x30, 0x34, 0x31, 0x31, 0x33, 0x37, 0x30, 0x37, 0x5A, 0x30, 0x6E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x38, 0x36, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x47, 0x75, 0x61, 0x6E, 0x67, 0x20, 0x44, 0x6F, 0x6E, 0x67, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x53, 0x68, 0x65, 0x6E, 0x20, 0x5A, 0x68, 0x65, 0x6E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x54, 0x65, 0x6E, 0x63, 0x65, 0x6E, 0x74, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x07, 0x54, 0x65, 0x6E, 0x63, 0x65, 0x6E, 0x74, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x48, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x20, 0x4C, 0x75, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xA0, 0xB5, 0x24, 0x12, 0x89, 0x22, 0x73, 0x95, 0x9D, 0x91, 0xAA, 0x31, 0x66, 0xCC, 0x35, 0x92, 0x26, 0x30, 0xA9, 0xE6, 0xBA, 0xB3, 0x94, 0xD8, 0x34, 0x1A, 0xBF, 0xEB, 0x08, 0x71, 0xE6, 0x15, 0x25, 0xF3, 0x9D, 0x21, 0x64, 0xA7, 0x48, 0x06, 0x3F, 0x28, 0x3E, 0xDC, 0x73, 0x35, 0x25, 0x76, 0x33, 0x2B, 0x4A, 0x24, 0x9A, 0x3A, 0x83, 0x11, 0xFA, 0xA3, 0x53, 0x35, 0x58, 0x5B, 0xA2, 0x31, 0x7C, 0xDA, 0x09, 0x3B, 0x44, 0x28, 0x4F, 0x13, 0xDB, 0x00, 0x12, 0x9F, 0x13, 0x35, 0x04, 0x9D, 0x72, 0x5B, 0xB2, 0x88, 0x64, 0xC3, 0xCF, 0x65, 0x51, 0xA8, 0xB4, 0x07, 0x2C, 0x76, 0x16, 0x0B, 0x0F, 0xD4, 0x71, 0xAD, 0x1D, 0x2D, 0xE6, 0x40, 0xDE, 0x79, 0x15, 0xF6, 0x94, 0x15, 0x5C, 0x3A, 0x1B, 0x28, 0xFE, 0x01, 0x95, 0x3F, 0x7B, 0xAE, 0xBC, 0x1D, 0xB6, 0xEB, 0x49, 0xAA, 0x22, 0x71, 0xAB, 0xD2, 0xA7, 0xC3, 0xD3, 0xBA, 0x49, 0xDA, 0x94, 0xCC, 0x02, 0x98, 0x87, 0x44, 0x33, 0x1C, 0x51, 0x01, 0x2D, 0xC8, 0xE3, 0x8D, 0xD9, 0xEB, 0x13, 0x3C, 0x75, 0xE5, 0x30, 0x4E, 0xE6, 0x7D, 0x40, 0x48, 0xB0, 0x00, 0xFD, 0x5B, 0x03, 0xCB, 0x64, 0xA3, 0x50, 0x05, 0xC9, 0x76, 0x42, 0x47, 0xD6, 0x84, 0x08, 0xF9, 0xD7, 0x16, 0x7A, 0x6E, 0x91, 0xB1, 0x05, 0x21, 0xD7, 0xCC, 0xE6, 0x21, 0x71, 0xFB, 0x87, 0x60, 0x69, 0x2D, 0xED, 0x25, 0xFA, 0xE6, 0x61, 0x35, 0x4F, 0x93, 0x9A, 0x87, 0x56, 0x5B, 0x37, 0x70, 0x15, 0xCA, 0x8D, 0x5D, 0x6A, 0x11, 0x39, 0x6F, 0xB1, 0x5D, 0x7C, 0x4C, 0xFD, 0xD6, 0xBD, 0x01, 0xEB, 0x0D, 0x0B, 0x78, 0xFF, 0xF2, 0x5B, 0x74, 0xB0, 0xBE, 0x70, 0xC7, 0xE0, 0x21, 0xDB, 0x30, 0x17, 0xA5, 0xB0, 0xFB, 0xAC, 0x47, 0xD5, 0x74, 0xEE, 0xE8, 0x4E, 0x35, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x21, 0x30, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x04, 0xE1, 0xEB, 0xE8, 0xEF, 0xC6, 0x0E, 0x3D, 0x09, 0x80, 0x55, 0x6A, 0xCD, 0x1C, 0x28, 0x6A, 0x86, 0x37, 0x0C, 0xC2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x08, 0x15, 0xF3, 0x20, 0xB4, 0x3A, 0x17, 0x58, 0x0F, 0x8F, 0x98, 0x9D, 0x37, 0x6D, 0xC0, 0x59, 0x72, 0x6D, 0x5D, 0xE6, 0x0C, 0xA3, 0xBA, 0x34, 0x02, 0x0C, 0xF8, 0xB6, 0xAD, 0xBD, 0xDA, 0xD6, 0xFE, 0xA5, 0x77, 0xB3, 0x52, 0x0E, 0x8E, 0xF5, 0x01, 0xA7, 0xC1, 0x26, 0xE8, 0x92, 0x2B, 0xBC, 0x72, 0x13, 0xCB, 0xA3, 0x73, 0x18, 0xFA, 0xCA, 0x3C, 0xC6, 0x17, 0xDA, 0x03, 0x01, 0x0F, 0xCF, 0xEF, 0x8E, 0x31, 0xB3, 0x46, 0xDA, 0x52, 0x4B, 0x32, 0x68, 0x6E, 0x23, 0x96, 0x58, 0xCF, 0xB7, 0xF8, 0x6D, 0x30, 0x95, 0x31, 0x41, 0xCE, 0x12, 0x8B, 0x49, 0x1E, 0x62, 0xB6, 0x61, 0xA4, 0x3F, 0x82, 0x4B, 0xBE, 0xAE, 0xBF, 0xFD, 0x26, 0xF4, 0x94, 0x31, 0x67, 0x2B, 0x86, 0xC3, 0x86, 0x77, 0xCE, 0x32, 0x35, 0x5C, 0xAB, 0x20, 0x08, 0xE8, 0x4B, 0x3E, 0x3E, 0x13, 0x8F, 0xC9, 0x15, 0x03, 0x34, 0xB1, 0x2E, 0xF1, 0x78, 0xE3, 0xA5, 0xC2, 0x88, 0xCD, 0x2B, 0xF2, 0x6E, 0x3E, 0x4B, 0x1D, 0x1B, 0xDC, 0x11, 0x4D, 0x8A, 0x8F, 0xD5, 0x87, 0xF3, 0x1C, 0xF3, 0x13, 0x74, 0x28, 0x1E, 0x9C, 0x77, 0xE6, 0x3C, 0xE1, 0x72, 0x7A, 0x6D, 0x12, 0xB2, 0xF3, 0xDF, 0xA5, 0xD9, 0xA8, 0xA5, 0xAE, 0x86, 0x73, 0x6A, 0x12, 0xE3, 0x20, 0xC8, 0x83, 0x76, 0xD7, 0x8C, 0x97, 0xC2, 0x52, 0x84, 0xAC, 0xF4, 0x4A, 0xE5, 0xB3, 0x99, 0x46, 0xBE, 0x9C, 0xF7, 0x7C, 0xF1, 0xC1, 0x06, 0xFA, 0x71, 0x26, 0xCA, 0x56, 0xB4, 0x59, 0x6E, 0x8E, 0x47, 0xCC, 0x65, 0x86, 0xF3, 0x11, 0x0F, 0x49, 0xA7, 0x98, 0x31, 0x8F, 0x2B, 0xBE, 0x28, 0xAC, 0x5C, 0xFB, 0x65, 0x9B, 0xA0, 0x13, 0xEE, 0x22, 0x66, 0x60, 0x68, 0x68, 0xAF, 0x5F, 0x64, 0x04, 0x84, 0x74, 0x1C, 0x8F, 0x55, 0xDE, 0x7C, 0xF4, 0xE8, 0x5B}};

namespace APKKiller {
    JNIEnv *g_env;
    jstring g_apkPath;
    jobject g_packageManager;
    std::string g_apkPkg;

    class Reference {
    public:
        jobject reference;
    public:
        Reference(jobject reference) {
            this->reference = reference;
        }

        jobject getObj() {
            return g_env->CallObjectMethod(reference, g_env->GetMethodID(g_env->FindClass("java/lang/ref/Reference"), "get", "()Ljava/lang/Object;"));
        }
    };

    class WeakReference : public Reference {
    public:
        WeakReference(jobject weakReference) : Reference(weakReference) {
        }

        static jobject Create(jobject obj) {
            auto weakReferenceClass = g_env->FindClass("java/lang/ref/WeakReference");
            auto weakReferenceClassConstructor = g_env->GetMethodID(weakReferenceClass, "<init>", "(Ljava/lang/Object;)V");
            return g_env->NewObject(weakReferenceClass, weakReferenceClassConstructor, obj);
        }
    };

    class ArrayList {
    private:
        jobject arrayList;
    public:
        ArrayList(jobject arrayList) {
            this->arrayList = arrayList;
        }

        jobject getObj() {
            return arrayList;
        }

        jobject get(int index) {
            return g_env->CallObjectMethod(arrayList, g_env->GetMethodID(g_env->FindClass("java/util/ArrayList"), "get", "(I)Ljava/lang/Object;"), index);
        }

        void set(int index, jobject value) {
            g_env->CallObjectMethod(arrayList, g_env->GetMethodID(g_env->FindClass("java/util/ArrayList"), "set", "(ILjava/lang/Object;)Ljava/lang/Object;"), index, value);
        }

        int size() {
            return g_env->CallIntMethod(arrayList, g_env->GetMethodID(g_env->FindClass("java/util/ArrayList"), "size", "()I"));
        }
    };

    class ArrayMap {
    private:
        jobject arrayMap;
    public:
        ArrayMap(jobject arrayMap) {
            this->arrayMap = arrayMap;
        }

        jobject getObj() {
            return arrayMap;
        }

        jobject keyAt(int index) {
            return g_env->CallObjectMethod(arrayMap, g_env->GetMethodID(g_env->FindClass("android/util/ArrayMap"), "keyAt", "(I)Ljava/lang/Object;"), index);
        }

        jobject valueAt(int index) {
            return g_env->CallObjectMethod(arrayMap, g_env->GetMethodID(g_env->FindClass("android/util/ArrayMap"), "valueAt", "(I)Ljava/lang/Object;"), index);
        }

        jobject setValueAt(int index, jobject value) {
            return g_env->CallObjectMethod(arrayMap, g_env->GetMethodID(g_env->FindClass("android/util/ArrayMap"), "setValueAt", "(ILjava/lang/Object;)Ljava/lang/Object;"), index, value);
        }

        int size() {
            return g_env->CallIntMethod(arrayMap, g_env->GetMethodID(g_env->FindClass("android/util/ArrayMap"), "size", "()I"));
        }
    };

    class Field {
    private:
        jobject field;
    public:
        Field(jobject field) {
            this->field = field;
        }

        jobject getField() {
            return field;
        }

        void setAccessible(jboolean accessible) {
            g_env->CallVoidMethod(field, g_env->GetMethodID(g_env->FindClass("java/lang/reflect/Field"), "setAccessible", "(Z)V"), accessible);
        }

        jobject get(jobject object) {
            return g_env->CallObjectMethod(field, g_env->GetMethodID(g_env->FindClass("java/lang/reflect/Field"), "get", "(Ljava/lang/Object;)Ljava/lang/Object;"), object);
        }

        void set(jobject object, jobject value) {
            g_env->CallVoidMethod(field, g_env->GetMethodID(g_env->FindClass("java/lang/reflect/Field"), "set", "(Ljava/lang/Object;Ljava/lang/Object;)V"), object, value);
        }
    };

    class Method {
    private:
        jobject method;
    public:
        Method(jobject method) {
            this->method = method;
        }

        jobject getMethod() {
            return method;
        }

        void setAccessible(jboolean accessible) {
            g_env->CallVoidMethod(method, g_env->GetMethodID(g_env->FindClass("java/lang/reflect/Method"), "setAccessible", "(Z)V"), accessible);
        }

        jobject invoke(jobject object, jobjectArray args = 0) {
            return g_env->CallObjectMethod(method, g_env->GetMethodID(g_env->FindClass("java/lang/reflect/Method"), "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), object, args);
        }
    };

    class Class {
    private:
        jobject clazz;
    public:
        Class(jobject clazz) {
            this->clazz = clazz;
        }

        jobject getClass() {
            return clazz;
        }

        static Class *forName(const char *s) {
            auto str = g_env->NewStringUTF(s);

            auto classClass = g_env->FindClass("java/lang/Class");
            auto forNameMethod = g_env->GetStaticMethodID(classClass, "forName", "(Ljava/lang/String;)Ljava/lang/Class;");

            auto clazz = new Class(g_env->CallStaticObjectMethod(classClass, forNameMethod, str));

            return clazz;
        }

        Field *getDeclaredField(const char *s) {
            auto str = g_env->NewStringUTF(s);

            auto classClass = g_env->FindClass("java/lang/Class");
            auto getDeclaredFieldMethod = g_env->GetMethodID(classClass, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");

            auto field = new Field(g_env->CallObjectMethod(clazz, getDeclaredFieldMethod, str));

            return field;
        }

        Method *getDeclaredMethod(const char *s, jobjectArray args = 0) {
            auto str = g_env->NewStringUTF(s);

            auto classClass = g_env->FindClass("java/lang/Class");
            auto getDeclaredMethodMethod = g_env->GetMethodID(classClass, "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");

            auto method = new Method(g_env->CallObjectMethod(clazz, getDeclaredMethodMethod, str, args));

            return method;
        }
    };
}

using namespace APKKiller;

int getAPILevel() {
    static int api_level = -1;
    if (api_level == -1) {
        char prop_value[PROP_VALUE_MAX];
        __system_property_get("ro.build.version.sdk", prop_value);
        api_level = atoi(prop_value);
    }
    return api_level;
}

jobject getApplicationContext(jobject obj) {
    auto contextWrapperClass = g_env->FindClass("android/content/ContextWrapper");
    auto getApplicationContextMethod = g_env->GetMethodID(contextWrapperClass, "getApplicationContext", "()Landroid/content/Context;");
    return g_env->CallObjectMethod(obj, getApplicationContextMethod);
}

jobject getPackageManager(jobject obj) {
    auto contextClass = g_env->FindClass("android/content/Context");
    auto getPackageManagerMethod = g_env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    return g_env->CallObjectMethod(obj, getPackageManagerMethod);
}

std::string getPackageName(jobject obj) {
    auto contextClass = g_env->FindClass("android/content/Context");
    auto getPackageNameMethod = g_env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    auto packageName = (jstring) g_env->CallObjectMethod(obj, getPackageNameMethod);
    return g_env->GetStringUTFChars(packageName, 0);
}

bool Class_isInstanceOf(jobject obj, const char *className) {
    auto clazz = Class::forName(className);
    auto isInstanceOfMethod = g_env->GetMethodID(g_env->FindClass("java/lang/Class"), "isInstance", "(Ljava/lang/Object;)Z");
    return g_env->CallBooleanMethod(clazz->getClass(), isInstanceOfMethod, obj);
}

void patch_ApplicationInfo(jobject obj) {
    if (!obj) return;
    LOGI("-------- Patching ApplicationInfo - %p", obj);
    auto applicationInfoClass = Class::forName("android.content.pm.ApplicationInfo");

    auto sourceDirField = applicationInfoClass->getDeclaredField("sourceDir");
    sourceDirField->setAccessible(true);

    auto publicSourceDirField = applicationInfoClass->getDeclaredField("publicSourceDir");
    publicSourceDirField->setAccessible(true);

    sourceDirField->set(obj, g_apkPath);
    publicSourceDirField->set(obj, g_apkPath);

    if (getAPILevel() >= 21) {
        auto splitSourceDirsField = applicationInfoClass->getDeclaredField("splitSourceDirs");
        splitSourceDirsField->setAccessible(true);
        auto splitPublicSourceDirsField = applicationInfoClass->getDeclaredField("splitPublicSourceDirs");
        splitPublicSourceDirsField->setAccessible(true);

        // print both source dirs
        auto splitSourceDirs = (jobjectArray) splitSourceDirsField->get(obj); // jstringArray
        auto splitPublicSourceDirs = (jobjectArray) splitPublicSourceDirsField->get(obj); // jstringArray
        if (splitSourceDirs) {
            for (int i = 0; i < g_env->GetArrayLength(splitSourceDirs); i++) {
                auto splitSourceDir = (jstring) g_env->GetObjectArrayElement(splitSourceDirs, i);
                LOGI("-------- Split source dir[%d]: %s", i, g_env->GetStringUTFChars(splitSourceDir, 0));
                g_env->SetObjectArrayElement(splitSourceDirs, i, g_apkPath);
            }
            splitSourceDirsField->set(obj, splitSourceDirs);
        }
        if (splitSourceDirs) {
            for (int i = 0; i < g_env->GetArrayLength(splitPublicSourceDirs); i++) {
                auto splitPublicSourceDir = (jstring) g_env->GetObjectArrayElement(splitPublicSourceDirs, i);
                LOGI("-------- Split public source dir[%d]: %s", i, g_env->GetStringUTFChars(splitPublicSourceDir, 0));
                g_env->SetObjectArrayElement(splitPublicSourceDirs, i, g_apkPath);
            }
            splitPublicSourceDirsField->set(obj, splitPublicSourceDirs);
        }
    }
}

void patch_LoadedApk(jobject obj) {
    if (!obj) return;
    LOGI("-------- Patching LoadedApk - %p", obj);
    auto loadedApkClass = Class::forName("android.app.LoadedApk");

    auto mApplicationInfoField = loadedApkClass->getDeclaredField("mApplicationInfo");
    mApplicationInfoField->setAccessible(true);
    patch_ApplicationInfo(mApplicationInfoField->get(obj));

    auto mAppDirField = loadedApkClass->getDeclaredField("mAppDir");
    mAppDirField->setAccessible(true);

    auto mResDirField = loadedApkClass->getDeclaredField("mResDir");
    mResDirField->setAccessible(true);

    mAppDirField->set(obj, g_apkPath);
    mResDirField->set(obj, g_apkPath);
}

void patch_AppBindData(jobject obj) {
    if (!obj) return;
    LOGI("-------- Patching AppBindData - %p", obj);
    auto appBindDataClass = Class::forName("android.app.ActivityThread$AppBindData");

    auto infoField = appBindDataClass->getDeclaredField("info");
    infoField->setAccessible(true);
    patch_LoadedApk(infoField->get(obj));

    auto appInfoField = appBindDataClass->getDeclaredField("appInfo");
    appInfoField->setAccessible(true);
    patch_ApplicationInfo(appInfoField->get(obj));
}

void patch_ContextImpl(jobject obj) {
    if (!obj) return;
    if (Class_isInstanceOf(obj, "android.app.ContextImpl")) {
        LOGI("-------- Patching ContextImpl - %p", obj);
        auto contextImplClass = Class::forName("android.app.ContextImpl");
        auto mPackageInfoField = contextImplClass->getDeclaredField("mPackageInfo");
        mPackageInfoField->setAccessible(true);
    }
}

void patch_Application(jobject obj) {
    if (!obj) return;
    if (Class_isInstanceOf(obj, "android.app.Application")) {
        LOGI("-------- Patching Application - %p", obj);
        auto applicationClass = Class::forName("android.app.Application");
        auto mLoadedApkField = applicationClass->getDeclaredField("mLoadedApk");
        mLoadedApkField->setAccessible(true);
        patch_LoadedApk(mLoadedApkField->get(obj));
    }

    patch_ContextImpl(getApplicationContext(obj)); // Don't use this if crashes
}

AAssetManager *g_assetManager;
void extractAsset(std::string assetName, std::string extractPath) {
    LOGI("-------- Extracting %s to %s", assetName.c_str(), extractPath.c_str());
    AAssetManager *assetManager = g_assetManager;
    AAsset *asset = AAssetManager_open(assetManager, assetName.c_str(), AASSET_MODE_UNKNOWN);
    if (!asset) {
        return;
    }

    int fd = open(extractPath.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        AAsset_close(asset);
        return;
    }

    const int BUFFER_SIZE = 512;
    char buffer[BUFFER_SIZE];
    int bytesRead = 0;
    while ((bytesRead = AAsset_read(asset, buffer, BUFFER_SIZE)) > 0) {
        int bytesWritten = write(fd, buffer, bytesRead);
        if (bytesWritten != bytesRead) {
            AAsset_close(asset);
            close(fd);
            return;
        }
    }

    AAsset_close(asset);
    close(fd);
}

void patch_PackageManager(jobject obj) {
    if (!obj) return;

    auto activityThreadClass = Class::forName("android.app.ActivityThread");
    auto sCurrentActivityThreadField = activityThreadClass->getDeclaredField("sCurrentActivityThread");
    sCurrentActivityThreadField->setAccessible(true);
    auto sCurrentActivityThread = sCurrentActivityThreadField->get(NULL);

    auto sPackageManagerField = activityThreadClass->getDeclaredField("sPackageManager");
    sPackageManagerField->setAccessible(true);
    g_packageManager = g_env->NewGlobalRef(sPackageManagerField->get(sCurrentActivityThread));

    auto iPackageManagerClass = Class::forName("android.content.pm.IPackageManager");

    auto classClass = g_env->FindClass("java/lang/Class");
    auto getClassLoaderMethod = g_env->GetMethodID(classClass, "getClassLoader", "()Ljava/lang/ClassLoader;");

    auto classLoader = g_env->CallObjectMethod(iPackageManagerClass->getClass(), getClassLoaderMethod);
    auto classArray = g_env->NewObjectArray(1, classClass, NULL);
    g_env->SetObjectArrayElement(classArray, 0, iPackageManagerClass->getClass());

    auto apkKillerClass = g_env->FindClass("com/kuro/APKKiller");
    auto myInvocationHandlerField = g_env->GetStaticFieldID(apkKillerClass, "myInvocationHandler", "Ljava/lang/reflect/InvocationHandler;");
    auto myInvocationHandler = g_env->GetStaticObjectField(apkKillerClass, myInvocationHandlerField);

    auto proxyClass = g_env->FindClass("java/lang/reflect/Proxy");
    auto newProxyInstanceMethod = g_env->GetStaticMethodID(proxyClass, "newProxyInstance", "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;");
    auto proxy = g_env->CallStaticObjectMethod(proxyClass, newProxyInstanceMethod, classLoader, classArray, myInvocationHandler);

    sPackageManagerField->set(sCurrentActivityThread, proxy);

    auto pm = getPackageManager(obj);
    auto mPMField = Class::forName("android.app.ApplicationPackageManager")->getDeclaredField("mPM");
    mPMField->setAccessible(true);
    mPMField->set(pm, proxy);
}

void APKKill(JNIEnv *env, jclass clazz, jobject context) {
    LOGI("-------- Killing APK");

    APKKiller::g_env = env;
    g_assetManager = AAssetManager_fromJava(env,env->CallObjectMethod(context,env->GetMethodID(env->FindClass("android/content/Context"), "getAssets", "()Landroid/content/res/AssetManager;")));

    std::string apkPkg = getPackageName(context);
    APKKiller::g_apkPkg = apkPkg;

    LOGI("-------- Killing %s", apkPkg.c_str());

    char apkDir[512];
    sprintf(apkDir, "/data/data/%s/cache", apkPkg.c_str());
    mkdir(apkDir, 0777);

    std::string apkPath = "/data/data/";
    apkPath += apkPkg;
    apkPath += "/cache/";
    apkPath += apk_fake_name;

    if (access(apkPath.c_str(), F_OK) == -1) {
        extractAsset(apk_asset_path, apkPath);
    }

    APKKiller::g_apkPath = (jstring) env->NewGlobalRef(g_env->NewStringUTF(apkPath.c_str()));
    patch_PackageManager(context);

    auto activityThreadClass = Class::forName("android.app.ActivityThread");
    auto sCurrentActivityThreadField = activityThreadClass->getDeclaredField("sCurrentActivityThread");
    sCurrentActivityThreadField->setAccessible(true);
    auto sCurrentActivityThread = sCurrentActivityThreadField->get(NULL);

    auto mBoundApplicationField = activityThreadClass->getDeclaredField("mBoundApplication");
    mBoundApplicationField->setAccessible(true);
    patch_AppBindData(mBoundApplicationField->get(sCurrentActivityThread));

    auto mInitialApplicationField = activityThreadClass->getDeclaredField("mInitialApplication");
    mInitialApplicationField->setAccessible(true);
    patch_Application(mInitialApplicationField->get(sCurrentActivityThread));

    auto mAllApplicationsField = activityThreadClass->getDeclaredField("mAllApplications");
    mAllApplicationsField->setAccessible(true);
    auto mAllApplications = mAllApplicationsField->get(sCurrentActivityThread);
    ArrayList *list = new ArrayList(mAllApplications);
    for(int i = 0; i < list->size(); i++) {
        auto application = list->get(i);
        patch_Application(application);
        list->set(i, application);
    }
    mAllApplicationsField->set(sCurrentActivityThread, list->getObj());

    auto mPackagesField = activityThreadClass->getDeclaredField("mPackages");
    mPackagesField->setAccessible(true);
    auto mPackages = mPackagesField->get(sCurrentActivityThread);
    ArrayMap *map = new ArrayMap(mPackages);
    for(int i = 0; i < map->size(); i++) {
        auto loadedApk = new WeakReference(map->valueAt(i));
        patch_LoadedApk(loadedApk->getObj());
        map->setValueAt(i, WeakReference::Create(loadedApk->getObj()));
    }
    mPackagesField->set(sCurrentActivityThread, map->getObj());

    auto mResourcePackagesField = activityThreadClass->getDeclaredField("mResourcePackages");
    mResourcePackagesField->setAccessible(true);
    auto mResourcePackages = mResourcePackagesField->get(sCurrentActivityThread);
    map = new ArrayMap(mResourcePackages);
    for(int i = 0; i < map->size(); i++) {
        auto loadedApk = new WeakReference(map->valueAt(i));
        patch_LoadedApk(loadedApk->getObj());
        map->setValueAt(i, WeakReference::Create(loadedApk->getObj()));
    }
    mResourcePackagesField->set(sCurrentActivityThread, map->getObj());

    patch_ContextImpl(context); // Don't use this if crashes
}

jobject nativeInvoke(JNIEnv *env, jclass clazz, jobject proxy, jobject method, jobjectArray args) {
    auto Method_getName = [env](jobject method) {
        return env->CallObjectMethod(method, env->GetMethodID(env->FindClass("java/lang/reflect/Method"), "getName", "()Ljava/lang/String;"));
    };

    auto Method_invoke = [env](jobject method, jobject obj, jobjectArray args) {
        return env->CallObjectMethod(method, env->GetMethodID(env->FindClass("java/lang/reflect/Method"), "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), obj, args);
    };

    auto Integer_intValue = [env](jobject integer) {
        return env->CallIntMethod(integer, env->GetMethodID(env->FindClass("java/lang/Integer"), "intValue", "()I"));
    };

    const char *Name = env->GetStringUTFChars((jstring) Method_getName(method), NULL);
    if(!strcmp(Name, "getPackageInfo")) {
        const char *packageName = env->GetStringUTFChars((jstring) env->GetObjectArrayElement(args, 0), NULL);
        int flags = Integer_intValue(env->GetObjectArrayElement(args, 1));
        if (!strcmp(packageName, g_apkPkg.c_str())) {
            if ((flags & 0x40) != 0) {
                auto packageInfo = Method_invoke(method, g_packageManager, args);
                if (packageInfo) {
                    auto packageInfoClass = env->FindClass("android/content/pm/PackageInfo");
                    auto signaturesField = env->GetFieldID(packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");

                    auto signatureClass = env->FindClass("android/content/pm/Signature");
                    auto signatureConstructor = env->GetMethodID(signatureClass, "<init>", "([B)V");
                    auto signatureArray = env->NewObjectArray(apk_signatures.size(), signatureClass, NULL);
                    for (int i = 0; i < apk_signatures.size(); i++) {
                        auto signature = env->NewByteArray(apk_signatures[i].size());
                        env->SetByteArrayRegion(signature, 0, apk_signatures[i].size(), (jbyte *) apk_signatures[i].data());
                        env->SetObjectArrayElement(signatureArray, i, env->NewObject(signatureClass, signatureConstructor, signature));
                    }
                    env->SetObjectField(packageInfo, signaturesField, signatureArray);
                }
                return packageInfo;
            }
            if ((flags & 0x8000000) != 0) {
                return 0;
            }
        }
    } else if (!strcmp(Name, "getApplicationInfo")) {
        const char *packageName = env->GetStringUTFChars((jstring) env->GetObjectArrayElement(args, 0), NULL);
        if (!strcmp(packageName, g_apkPkg.c_str())) {
            auto applicationInfo = Method_invoke(method, g_packageManager, args);
            if (applicationInfo) {
                auto applicationInfoClass = env->FindClass("android/content/pm/ApplicationInfo");
                auto sourceDirField = env->GetFieldID(applicationInfoClass, "sourceDir", "Ljava/lang/String;");
                auto publicSourceDirField = env->GetFieldID(applicationInfoClass, "publicSourceDir", "Ljava/lang/String;");

                env->SetObjectField(applicationInfo, sourceDirField, g_apkPath);
                env->SetObjectField(applicationInfo, publicSourceDirField, g_apkPath);
            }
            return applicationInfo;
        }
    }
    return Method_invoke(method, g_packageManager, args);
}
```

I can't explain everything because there are a lot going on, but what's going is that those code will modify and fake various informations on the Java Internal classes using Reflection. By only using Application Context and original APK in the assets folder, you can easily bypass APK integrity and Signature check. Keep in mind that this doesn't bypass everything, games can also detect tampering using more complex system like syscall.

Add this class to your project, make sure to change it accordingly to your project configuration!
Java:
```java
package com.kuro;

import android.content.Context;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

@SuppressWarnings("all")
public class APKKiller {
    static {
        System.loadLibrary("kuro"); // You can change this according to your lib
    }

    public static native void Start(Context context);
    public static native Object nativeInvoke(Object obj, Method method, Object[] args);

    private static InvocationHandler myInvocationHandler = new InvocationHandler() {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            return nativeInvoke(proxy, method, args);
        }
    };
}
```

And don't forget to register the JNI Functions using this function:
C++:
```cpp
int RegisterFunctions(JNIEnv *env) {
    JNINativeMethod methods[2];
    methods[0].name = "Start";
    methods[0].signature = "(Landroid/content/Context;)V";
    methods[0].fnPtr = (void *) APKKill;

    methods[1].name = "nativeInvoke";
    methods[1].signature = "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;";
    methods[1].fnPtr = (void *) nativeInvoke;

    jclass clazz = env->FindClass("com/your_package/APKKiller");
    if (!clazz)
        return -1;

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) != 0)
        return -1;

    return 0;
}
```

And finally, load your lib to the game and thats it! I don't put the tutorial on how to put the source code completely, because I don't like spoonfeeding, so you do it ur own and enjoy the result!
Make sure to change some stuff like apk_signatures, you can get the apk signatures using this tool (Download):

1649454463610.png
After it generates new apk_signatures, make sure to change it in APKKiller.h.
Don't forget to put the game original APK in the asset folder, let's say if my apk_asset_path is "original.apk", then you have to put the game original apk in asset as "original.apk"

After you put the smali in the game, find "attachBaseContext" or "onCreate" and put this code:
attachBaseContext:
Code:
```smali
invoke-static {p1}, Lcom/xxx/APKKiller;->Start(Landroid/content/Context;)V
onCreate:
Code:
invoke-static {p0}, Lcom/xxx/APKKiller;->Start(Landroid/content/Context;)V
```
(change xxx to your package path)

All done! it should bypass simple APK and Signature verification :D

All credits are belong me! You can repost this but please put my name there :3
If there are any errors, you can come post the errors here and I'll provide help, thanks for reading uwu
Last edited: Apr 9, 2022
LikeLove
Reactions:
Raflihermawan, Virtualjssj, soheil-sh and 36 others
Kur0
