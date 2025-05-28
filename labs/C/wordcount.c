#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>


#define CEK_NULL(ptr, msg) \
  if (!ptr) { \
    fprintf(stderr, "%s\n", msg); \
    exit(1); \
  }

int main(int argc, char** argv) {

  if (argc < 2) {
    printf("usage: %s <file>\n", argv[0]);
    return 1;
  }

  FILE* file = fopen(argv[1], "r");
  CEK_NULL(file, "gagal memuat file");

  size_t words = 0;
  size_t lines = 0;
  size_t chars = 0;
  uint8_t in_word = 0;
  char buffer[1028];

  while(fgets(buffer, sizeof(buffer), file) != NULL) {
    lines++;

    for (size_t i = 0; buffer[i] != '\0'; i++) {
      chars++;

      if (isspace(buffer[i]) || buffer[i] == '\0')
        in_word = 0;

      else if (in_word == 0) {
        in_word = 1;
        words++;
      }

    }
  }

  fclose(file);

  printf("words: %d\n", words);
  printf("lines: %d\n", lines);
  printf("chars: %d\n", chars);
  printf("filename: %s\n", argv[1]);

  return 0;
}
