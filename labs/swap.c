#include <stdio.h>

void swapint(int*, int*);

int main() {
    int a = 5;
    int b = 7;

    printf("%d %d\n", a, b);

    swapint(&a, &b);

    printf("%d %d\n", a, b);

    return 0;
}

void swapint(int *x, int *y) {
    *x = *x ^ *y;
    *y = *x ^ *y;
    *x = *x ^ *y;
}
