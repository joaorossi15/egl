#include "pragma.h"
#include <string.h>

int scan_debug_pragma(const char *src) {
  const char *tmp = src;
  int debug_on = 0;

  while (*tmp) {
    if (strncmp(tmp, "policy", 6) == 0)
      break;

    while (*tmp == ' ' || *tmp == '\t')
      tmp++;

    const char *line = tmp;
    if (strncmp(line, "@debug", 6) == 0)
      debug_on = 1;

    while (*tmp && *tmp != '\n')
      tmp++;
    if (*tmp == '\n')
      tmp++;
  }

  return debug_on;
}
