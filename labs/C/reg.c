#include <regex.h>
#include <stdio.h>

void check_match(const char *pattern, const char *string) {
  regex_t regex;
  int ret;

  // Compile the regex
  ret = regcomp(&regex, pattern, REG_EXTENDED);
  if (ret) {
    printf("Could not compile regex\n");
    return;
  }

  // Execute regex match
  ret = regexec(&regex, string, 0, NULL, 0);
  if (!ret) {
    printf("Match found: %s\n", string);
  } else if (ret == REG_NOMATCH) {
    printf("No match found for: %s\n", string);
  } else {
    printf("Regex match error\n");
  }

  // Free memory
  regfree(&regex);
}

int main() {
  const char *pattern = "hello"; // Regex pattern
  check_match(pattern, "hello world");
  check_match(pattern, "goodbye");

  return 0;
}
