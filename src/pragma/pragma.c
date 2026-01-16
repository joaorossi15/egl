#include "pragma.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
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

static const char *skip_ws(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r')
    p++;
  return p;
}

static const char *skip_ws_commas(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == ',')
    p++;
  return p;
}

static int is_ident_start(char c) {
  return (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static int is_ident_char(char c) {
  return is_ident_start(c) || (c >= '0' && c <= '9');
}

static int parse_ident(const char *p, char *out, size_t cap,
                       const char **out_p) {
  if (!is_ident_start(*p))
    return 0;

  size_t k = 0;
  while (*p && is_ident_char(*p)) {
    if (k + 1 < cap)
      out[k++] = *p;
    p++;
  }
  out[k] = '\0';
  if (out_p)
    *out_p = p;
  return 1;
}

static int parse_quoted_string(const char *p, char *out, size_t cap,
                               const char **out_p) {
  if (*p != '"')
    return 0;
  p++; // skip "
  size_t k = 0;
  while (*p && *p != '"') {
    if (k + 1 < cap)
      out[k++] = *p;
    p++;
  }
  if (*p != '"')
    return 0;
  p++;
  out[k] = '\0';
  if (out_p)
    *out_p = p;
  return 1;
}

static int parse_float(const char *p, float *out, const char **out_p) {
  char *end = NULL;
  float v = strtof(p, &end);
  if (end == p)
    return 0;
  if (out)
    *out = v;
  if (out_p)
    *out_p = end;
  return 1;
}

int scan_detector_pragmas(const char *src, detector_pragma_cb cb, void *ctx) {
  if (!src || !cb)
    return 0;

  const char *p = src;
  int n = 0;

  while (*p) {
    p = skip_ws(p);

    if (strncmp(p, "policy", 6) == 0)
      break;

    if (strncmp(p, "@detector", 9) != 0) {
      const char *nl = strchr(p, '\n');
      if (!nl)
        break;
      p = nl + 1;
      continue;
    }

    p += 9;
    p = skip_ws(p);

    if (*p != '(') {
      const char *nl = strchr(p, '\n');
      if (!nl)
        break;
      p = nl + 1;
      continue;
    }
    p++; // '('
    p = skip_ws(p);

    char category[64] = {0};
    if (!parse_ident(p, category, sizeof(category), &p)) {
      const char *nl = strchr(p, '\n');
      if (!nl)
        break;
      p = nl + 1;
      continue;
    }

    char backend[64] = {0};
    char model[256] = {0};
    float threshold = -1.0f;

    while (*p && *p != ')') {
      p = skip_ws_commas(p);
      if (*p == ')')
        break;

      char key[64] = {0};
      if (!parse_ident(p, key, sizeof(key), &p))
        break;

      p = skip_ws(p);
      if (*p != '=')
        break;
      p++;
      p = skip_ws(p);

      if (strcmp(key, "backend") == 0) {
        if (!parse_quoted_string(p, backend, sizeof(backend), &p)) {
          if (!parse_ident(p, backend, sizeof(backend), &p))
            break;
        }
      } else if (strcmp(key, "model") == 0) {
        if (!parse_quoted_string(p, model, sizeof(model), &p))
          break;
      } else if (strcmp(key, "threshold") == 0) {
        if (!parse_float(p, &threshold, &p))
          break;
      } else {
        char tmp[256];
        const char *np = NULL;
        if (parse_quoted_string(p, tmp, sizeof(tmp), &np)) {
          p = np;
        } else if (parse_ident(p, tmp, sizeof(tmp), &np)) {
          p = np;
        } else {
          float dummy;
          if (parse_float(p, &dummy, &np))
            p = np;
          else
            break;
        }
      }

      p = skip_ws_commas(p);
    }

    if (*p == ')')
      p++;

    if (cb(category, model, threshold, ctx) == 0)
      n++;

    const char *nl = strchr(p, '\n');
    if (!nl)
      break;
    p = nl + 1;
  }

  return n;
}
