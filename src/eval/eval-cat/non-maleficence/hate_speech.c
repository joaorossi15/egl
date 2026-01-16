#define _POSIX_C_SOURCE 200809L
#include "../../eval.h"
#include "../helpers/helper.h"
#include "runtime.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int py_hate_speech_score(const char *py_bin, const char *py_script,
                                const char *text, const char *model_opt,
                                float *out_score) {
  if (!py_bin || !py_script || !text || !out_score)
    return ERROR;

  char in_path[] = "/tmp/egl_hate_speech_XXXXXX";
  int fd = mkstemp(in_path);
  if (fd < 0) {
    fprintf(stderr, "[py] mkstemp failed\n");
    return ERROR;
  }

  FILE *in = fdopen(fd, "w");
  if (!in) {
    fprintf(stderr, "[py] fdopen failed\n");
    close(fd);
    unlink(in_path);
    return ERROR;
  }

  fputs(text, in);
  fputc('\n', in);
  fclose(in);

  char cmd[1600];

  if (model_opt && model_opt[0]) {
    snprintf(cmd, sizeof(cmd), "%s %s --in %s --model \"%s", py_bin, py_script,
             in_path, model_opt);
  } else {
    snprintf(cmd, sizeof(cmd), "%s %s --in %s", py_bin, py_script, in_path);
  }

  FILE *fp = popen(cmd, "r");
  if (!fp) {
    fprintf(stderr, "[py] popen failed\n");
    unlink(in_path);
    return ERROR;
  }

  char buf[512];
  int parsed = 0;
  float score = 0.0f;

  while (fgets(buf, sizeof(buf), fp)) {
    char *s = buf;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
      s++;

    errno = 0;
    char *endptr = NULL;
    float v = strtof(s, &endptr);

    if (errno == 0 && endptr != s) {
      score = v;
      parsed = 1;
      break;
    }
  }

  int prc = pclose(fp);
  (void)prc;

  unlink(in_path);

  if (!parsed) {
    fprintf(stderr, "[py] no parseable float from python output\n");
    return ERROR;
  }

  *out_score = score;
  return OK;
}

int handler_hate_speech(int flag, int cat_id, PolicyRunTime *prt) {
  if (!prt || !prt->buf)
    return ERROR;

  const char *py_bin = "python3";
  const char *py_script = "src/eval/scripts/hate_speech_score.py";

  float thr = -1.0;
  if (prt->det_threshold[cat_id] >= 0.0f) {
    thr = prt->det_threshold[cat_id];
  } else {
    thr = (prt->aggr) ? 0.7f : 0.85f;
  }

  const char *model_opt = NULL;
  if (prt->det_model[cat_id][0]) {
    model_opt = prt->det_model[cat_id];
  }

  float score = 0.0f;
  int rc = py_hate_speech_score(py_bin, py_script, prt->buf, model_opt, &score);
  if (rc != OK)
    return ERROR;

  prt->last_cat_id = cat_id;
  prt->last_backend = DET_BACKEND_PROBABILISTIC;
  prt->last_score = score;
  prt->last_threshold = thr;

  int matched = (score >= thr);
  if (!matched)
    return OK;

  int act = action_from_flag(flag);
  if (act >= 0) {
    prt->counts[act][cat_id] += 1;
    prt->total_by_action[act] += 1;
  }

  switch (flag) {
  case FORBID_FLAG:
    return FORBID_VIOLATION;

  case REDACT_FLAG: {
    StrView mask = prt->mask_redact[cat_id];
    char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';
    memset(prt->buf, c, strlen(prt->buf));
    return OK;
  }

  case APPEND_FLAG: {
    StrView app = prt->append_string[cat_id];
    if (app.ptr && app.len > 0) {
      size_t cur_len = strlen(prt->buf);
      size_t need = cur_len + 1 + (size_t)app.len + 1;
      if (!ensure_cap(prt, need))
        return ERROR;

      prt->buf[cur_len] = ' ';
      memcpy(prt->buf + cur_len + 1, app.ptr, (size_t)app.len);
      prt->buf[cur_len + 1 + app.len] = '\0';
    }
    return OK;
  }

  default:
    return ERROR;
  }
}
