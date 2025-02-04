// Find the sum of complex numbers
#include <stdio.h>

typedef struct Complex {
  double real;
  double imag;
} complex;

complex addNumbers(complex c1, complex c2) {
  complex sum;
  sum.real = c1.real + c2.real;
  sum.imag = c1.imag + c2.imag;
  return sum;
}

int main() {
  complex c1 = {1.4, 4.5}, c2 = {5.4, -3.4};
  complex result;
  result = addNumbers(c1, c2);
  printf("result = %.1lf + %.1lfi",
         result.real, result.imag);

  return 0;
}
