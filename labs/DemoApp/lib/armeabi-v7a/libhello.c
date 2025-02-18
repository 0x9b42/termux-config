#include <jni.h>
#include <string.h>

JNIEXPORT jstring JNICALL
Java_mob_demoapp_Main_sayHello(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, "Hello from C!");
}
