#include "pragma.h"
#include <string.h>

static int scan_pragma(const char *src, const char *tag) {
  const char *p = src;
  size_t taglen = strlen(tag);

  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == '\r')
      p++;

    if (strncmp(p, "policy", 6) == 0)
      break;

    if (strncmp(p, tag, taglen) == 0)
      return 1;

    const char *nl = strchr(p, '\n');
    if (!nl)
      break;
    p = nl + 1;
  }
  return 0;
}

int scan_debug_pragma(char *src) { return scan_pragma(src, "@debug"); }

int scan_aggressive_pragma(char *src) {
  return scan_pragma(src, "@aggressive");
}
