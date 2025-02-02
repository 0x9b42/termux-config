#include <stdio.h>
#include <string.h>

int main(int c, char** v) {
    char* pass = "abogoboga";
    char p[16];

    sprintf(p, "%s", v[1]);

    if (!strcmp(p, pass))
        puts("YES!");
    else
        puts("NO!");

    return 0;
}
