#include <stdio.h>

struct Employee {
  int age;
  double salary;
} person[3];

int main() {

  // take age and salary input of 3 persons
  for (int i = 0; i < 3; ++i) {

    printf("For employee %d: \n", i + 1);
    printf("Enter age: ");
    scanf("%d", &(person + i)->age);

    printf("Enter salary: ");
    scanf("%lf", &(person + i)->salary);
  }

  // print age and salary of 3 persons
  for (int i = 0; i < 3; ++i) {
    printf("Employee %d: ", i + 1);
    printf("age = %d, ", (person + i)->age);
    printf("salary = %.2lf\n", (person + i)->salary);
  }

  return 0;
}
