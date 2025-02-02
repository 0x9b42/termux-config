#include <stdio.h>
#include <android/log.h>

int main(int c, char**v) {
    char const * txt = "Hello android\n";

    puts(txt);

    int prio = ANDROID_LOG_INFO;
    const char * tag = "hello_tag";

    __android_log_print(prio, tag, txt);
    return 0;
}
