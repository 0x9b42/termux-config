#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define BUFFER_SIZE 64

int main(void) {
    char guess_str[BUFFER_SIZE];
    int guess = 0;

    // Seed the RNG
    srand((unsigned int)time(NULL));
    int secret = (rand() % 100) + 1; // Range: 1 to 100

    // Prompt
    printf("please guess a number: ");
    fflush(stdout);

    // Read line
    if (fgets(guess_str, sizeof(guess_str), stdin) == NULL) {
        fprintf(stderr, "Failed to read line\n");
        return 1;
    }

    // Strip newline
    guess_str[strcspn(guess_str, "\n")] = '\0';

    // Validate input
    int is_valid = 1;
    for (size_t i = 0; guess_str[i]; i++) {
        if (i == 0 && guess_str[i] == '-') continue; // allow negative input
        if (!isdigit((unsigned char)guess_str[i])) {
            is_valid = 0;
            break;
        }
    }

    if (!is_valid) {
        fprintf(stderr, "Invalid input. Not a number.\n");
        return 1;
    }

    // Convert to int
    guess = atoi(guess_str);

    // Output
    printf("secret num. : %d\n", secret);
    printf("you guessed : %d\n", guess);

    return 0;
}
