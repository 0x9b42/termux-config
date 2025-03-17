#include <pcre.h>
#include <stdio.h>

int main() {
  const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
  const char *subject = "example@mail.com";
  const char *error;
  int erroffset;
  int ovector[30];
  int rc;

  // Compile the regex
  pcre *re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
  if (!re) {
    printf("Regex compilation failed at offset %d: %s\n", erroffset, error);
    return 1;
  }

  // Execute the regex
  rc = pcre_exec(re, NULL, subject, (int)strlen(subject), 0, 0, ovector, 30);
  if (rc >= 0) {
    printf("Match found: %s\n", subject);
  } else {
    printf("No match found.\n");
  }

  // Free memory
  pcre_free(re);
  return 0;
}
