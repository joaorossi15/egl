#define _POSIX_C_SOURCE 200809L
#include "../../eval.h"
#include "../helpers/helper.h"
#include "runtime.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  float score;
  float threshold;
  int spans_n;
  int spans_cap;
  int *spans;
} PyTaxOut;

static void pyout_free(PyTaxOut *o) {
  if (!o)
    return;
  free(o->spans);
  o->spans = NULL;
  o->spans_n = o->spans_cap = 0;
}

static int spans_push(PyTaxOut *o, int s, int e) {
  if (o->spans_n + 2 > o->spans_cap) {
    int new_cap = (o->spans_cap == 0) ? 16 : (o->spans_cap * 2);
    int *p = (int *)realloc(o->spans, (size_t)new_cap * sizeof(int));
    if (!p)
      return ERROR;
    o->spans = p;
    o->spans_cap = new_cap;
  }
  o->spans[o->spans_n++] = s;
  o->spans[o->spans_n++] = e;
  return OK;
}

static const char *skip_ws(const char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  return p;
}

static const char *find_key(const char *json, const char *key) {
  static char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  return strstr(json, needle);
}

static int parse_float_field(const char *json, const char *key, float *out) {
  const char *p = find_key(json, key);
  if (!p)
    return ERROR;
  p = strchr(p, ':');
  if (!p)
    return ERROR;
  p = skip_ws(p + 1);
  errno = 0;
  char *end = NULL;
  float v = strtof(p, &end);
  if (errno != 0 || end == p)
    return ERROR;
  *out = v;
  return OK;
}

static int parse_spans(const char *json, PyTaxOut *o) {
  const char *p = find_key(json, "spans");
  if (!p)
    return OK;
  p = strchr(p, ':');
  if (!p)
    return ERROR;
  p = skip_ws(p + 1);
  if (*p != '[')
    return ERROR;
  p++;

  while (*p) {
    p = skip_ws(p);
    if (*p == ']')
      return OK;
    if (*p == ',') {
      p++;
      continue;
    }

    if (*p != '[')
      return ERROR;
    p++;
    p = skip_ws(p);

    errno = 0;
    char *end1 = NULL;
    long s = strtol(p, &end1, 10);
    if (errno != 0 || end1 == p)
      return ERROR;
    p = skip_ws(end1);

    if (*p != ',')
      return ERROR;
    p++;
    p = skip_ws(p);

    errno = 0;
    char *end2 = NULL;
    long e = strtol(p, &end2, 10);
    if (errno != 0 || end2 == p)
      return ERROR;
    p = skip_ws(end2);

    if (*p != ']')
      return ERROR;
    p++;

    if (e > s && s >= 0) {
      if (spans_push(o, (int)s, (int)e) != OK)
        return ERROR;
    }
    p = skip_ws(p);
    if (*p == ',')
      p++;
  }
  return ERROR;
}

static int py_tax_id_eval(const char *py_bin, const char *py_script,
                          const char *text, float thr,
                          const char *custom_regex_or_null, PyTaxOut *out) {
  if (!py_bin || !py_script || !text || !out)
    return ERROR;

  memset(out, 0, sizeof(*out));
  out->score = 0.0f;
  out->threshold = thr;

  char in_path[] = "/tmp/egl_taxid_XXXXXX";
  int fd = mkstemp(in_path);
  if (fd < 0)
    return ERROR;

  FILE *in = fdopen(fd, "w");
  if (!in) {
    close(fd);
    unlink(in_path);
    return ERROR;
  }
  fputs(text, in);
  fputc('\n', in);
  fclose(in);

  char cmd[1800];

  if (custom_regex_or_null && custom_regex_or_null[0]) {
    snprintf(cmd, sizeof(cmd),
             "%s %s --in %s --threshold %.6f --custom-regex \"%s\" 2>/dev/null",
             py_bin, py_script, in_path, thr, custom_regex_or_null);
  } else {
    snprintf(cmd, sizeof(cmd), "%s %s --in %s --threshold %.6f 2>/dev/null",
             py_bin, py_script, in_path, thr);
  }

  FILE *fp = popen(cmd, "r");
  if (!fp) {
    unlink(in_path);
    return ERROR;
  }

  char buf[4096];
  if (!fgets(buf, sizeof(buf), fp)) {
    pclose(fp);
    unlink(in_path);
    return ERROR;
  }
  pclose(fp);
  unlink(in_path);

  float score = 0.0f;
  float pthr = thr;
  if (parse_float_field(buf, "score", &score) != OK)
    return ERROR;
  (void)parse_float_field(buf, "threshold", &pthr);
  if (parse_spans(buf, out) != OK)
    return ERROR;

  out->score = score;
  out->threshold = pthr;
  return OK;
}

int handler_tax_id(int flag, int cat_id, PolicyRunTime *prt) {
  if (!prt || !prt->buf)
    return ERROR;

  const char *py_bin = "python3";
  const char *py_script = "src/eval/scripts/tax_id.py";

  float thr = prt->det_threshold[cat_id];
  if (!(thr >= 0.0f && thr <= 1.0f))
    thr = detector_default_threshold(cat_id);

  const char *custom = NULL;
  if (prt->det_model[cat_id][0]) {
    custom = prt->det_model[cat_id];
    while (*custom == ' ')
      custom++;
  }

  PyTaxOut out = {0};
  int rc = py_tax_id_eval(py_bin, py_script, prt->buf, thr, custom, &out);
  if (rc != OK) {
    pyout_free(&out);
    return ERROR;
  }

  prt->last_cat_id = cat_id;
  prt->last_backend = DET_BACKEND_DETERMINISTIC;
  prt->last_score = out.score;
  prt->last_threshold = out.threshold;

  int matched = (out.score >= out.threshold);
  if (!matched) {
    pyout_free(&out);
    return OK;
  }

  int act = action_from_flag(flag);
  if (act >= 0) {
    prt->counts[act][cat_id] += 1;
    prt->total_by_action[act] += 1;
  }

  switch (flag) {
  case FORBID_FLAG:
    pyout_free(&out);
    return FORBID_VIOLATION;

  case REDACT_FLAG: {
    StrView mask = prt->mask_redact[cat_id];
    char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';

    size_t L = strlen(prt->buf);
    if (out.spans_n < 2) {
      // safe fallback
      memset(prt->buf, c, L);
      pyout_free(&out);
      return OK;
    }

    for (int i = 0; i + 1 < out.spans_n; i += 2) {
      int s = out.spans[i];
      int e = out.spans[i + 1];
      if (s < 0)
        s = 0;
      if (e < 0)
        e = 0;
      if ((size_t)s > L)
        continue;
      if ((size_t)e > L)
        e = (int)L;
      if (e > s)
        memset(prt->buf + s, c, (size_t)(e - s));
    }

    pyout_free(&out);
    return OK;
  }

  case APPEND_FLAG: {
    StrView app = prt->append_string[cat_id];
    if (app.ptr && app.len > 0) {
      size_t cur_len = strlen(prt->buf);
      size_t need = cur_len + 1 + (size_t)app.len + 1;
      if (!ensure_cap(prt, need)) {
        pyout_free(&out);
        return ERROR;
      }
      prt->buf[cur_len] = ' ';
      memcpy(prt->buf + cur_len + 1, app.ptr, (size_t)app.len);
      prt->buf[cur_len + 1 + app.len] = '\0';
    }
    pyout_free(&out);
    return OK;
  }

  default:
    pyout_free(&out);
    return ERROR;
  }
}
