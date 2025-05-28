#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define CEK_NULL(ptr, msg) \
  if (!ptr) { \
    fprintf(stderr, "%s\n", msg); \
    exit(1); \
  }


void swapext(const char*, const char*);


int main(int argc, char** argv) {

  if (argc < 3) {
    fprintf(stderr, "usage: %s <file> <ext>\n", argv[0]);
    return 1;
  }

  swapext(argv[1], argv[2]);

  return 0;
}



void swapext(const char* fname, const char* newext) {

  // find the last dot in the filename
  const char* dot = strrchr(fname, '.');
  size_t base_len = dot ?
    (size_t)(dot - fname) : strlen(fname);


  // allocate buffer for new name
  char* newname = malloc(base_len + strlen(newext) + 2);
  CEK_NULL(newname, "error allocating newname");

  // copy base name and add new extension
  strncpy(newname, fname, base_len);
  newname[base_len] = '\0';
  strcat(newname, ".");
  strcat(newname, newext);

  // rename the file
  if (rename(fname, newname) != 0)
    perror("rename");

  else
    printf("%s renamed to %s\n", fname, newname);

  free(newname);
}
