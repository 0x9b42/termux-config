#include <stdio.h>

int main() {
    int *pn, n;
    n = 5;
    pn = &n;

    printf("%d\t", n);
    *pn = 7;


    printf("%d\t", n);

    return 0;
}
