#include <regex.h>
#include <stdio.h>

void extract_match(const char *pattern, const char *string) {
  regex_t regex;
  regmatch_t matches[2]; // For one captured group
  int ret;

  regcomp(&regex, pattern, REG_EXTENDED);
  ret = regexec(&regex, string, 2, matches, 0);

  if (!ret) {
    printf("Match found!\n");
    printf("Full match: %.*s\n", matches[0].rm_eo - matches[0].rm_so,
           string + matches[0].rm_so);
    if (matches[1].rm_so != -1) {
      printf("Captured group: %.*s\n", matches[1].rm_eo - matches[1].rm_so,
             string + matches[1].rm_so);
    }
  } else {
    printf("No match found.\n");
  }

  regfree(&regex);
}

int main() {
  const char *pattern = "Hello (\\w+)";
  extract_match(pattern, "Hello World!");
  return 0;
}
