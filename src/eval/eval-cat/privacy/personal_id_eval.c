#define PCRE2_CODE_UNIT_WIDTH 8
#include "../../eval.h"
#include "../helpers/helper.h"
#include "parser.h"
#include "runtime.h"
#include <ctype.h>
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int handler_phone(int flag, int cat_id, PolicyRunTime *prt) {
  static pcre2_code *re = NULL;
  short re_ready = 0;
  short saw_forbid = 0;

  if (!re_ready) {
    PCRE2_SIZE erroff = 0;
    int errcode = 0;
    PCRE2_SPTR pat = (PCRE2_SPTR) "(?:\\+|00)?[1-9](?:[0-9 \\-()]*\\d){7,14}";
    re = pcre2_compile(pat, PCRE2_ZERO_TERMINATED, 0, &errcode, &erroff, NULL);
    if (!re)
      return ERROR;
    re_ready = 1;
  }

  size_t len = strlen(prt->buf);
  size_t off = 0;
  int found = 0;

  pcre2_match_data *md = pcre2_match_data_create(8, NULL);
  if (!md)
    return ERROR;

  while (off < len) {

    int rc = pcre2_match(re, (PCRE2_SPTR)(prt->buf + off), len - off, 0, 0, md,
                         NULL);

    if (rc < 0) {
      off++;
      continue;
    }

    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
    size_t s = off + ov[0];
    size_t e = off + ov[1];
    if (e <= s) {
      off++;
      continue;
    }

    if (s > 0 && e < len &&
        (isalnum(prt->buf[s - 1]) || isalnum(prt->buf[e]))) {
      off = e;
      continue;
    }

    found = 1;

    int act = action_from_flag(flag);
    if (act >= 0) {
      prt->counts[act][cat_id] += 1;
      prt->total_by_action[act] += 1;
    }

    switch (flag) {
    case FORBID_FLAG:
      saw_forbid++;
      break;
    case REDACT_FLAG: {
      StrView mask = prt->mask_redact[cat_id];
      char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';
      memset(prt->buf + s, c, e - s);
      break;
    }
    case APPEND_FLAG:
      break;
    default:
      return ERROR;
    }
    off = e;
  }

  pcre2_match_data_free(md);

  if (found && saw_forbid)
    return FORBID_VIOLATION;

  if (found && flag == APPEND_FLAG) {
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
  }
  return OK;
}

int handler_email(int flag, int cat_id, PolicyRunTime *prt) {
  char *tmp = prt->buf;
  int found = 0;
  short saw_forbid = 0;

  while ((tmp = strchr(tmp, '@')) != NULL) {
    if (tmp == prt->buf) {
      tmp++;
      continue;
    }

    char *left_segment = tmp - 1;

    while (left_segment >= prt->buf &&
           (isalnum((unsigned char)*left_segment) || *left_segment == '_' ||
            *left_segment == '.' || *left_segment == '%' ||
            *left_segment == '+' || *left_segment == '-')) {
      left_segment--;
    }

    left_segment++;

    if (left_segment == tmp) {
      tmp++;
      continue;
    }

    char *right_segment = tmp + 1;
    int is_dot = 0;
    if (!isalnum((unsigned char)*right_segment)) {
      tmp++;
      continue;
    }

    while (*right_segment && (isalnum((unsigned char)*right_segment) ||
                              *right_segment == '-' || *right_segment == '.')) {
      if (*right_segment == '.') {
        is_dot = 1;
      }
      right_segment++;
    }

    if (!is_dot || (!isalpha((unsigned char)right_segment[-1]))) {
      tmp++;
      continue;
    }

    found = 1;

    int act = action_from_flag(flag);
    if (act >= 0) {
      prt->counts[act][cat_id] += 1;
      prt->total_by_action[act] += 1;
    }

    switch (flag) {
    case FORBID_FLAG:
      saw_forbid++;
      break;
    case REDACT_FLAG: {
      StrView mask = prt->mask_redact[cat_id];
      char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';
      size_t n = (size_t)(right_segment - left_segment);
      memset(left_segment, c, n);
      break;
    }
    case APPEND_FLAG:
      break;
    default:
      return ERROR;
    }
    tmp = right_segment;
  }

  if (found && saw_forbid)
    return FORBID_VIOLATION;

  if (found && flag == APPEND_FLAG) {
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
  }
  return OK;
}

int handler_personal_id(int flag, int cat_id, PolicyRunTime *prt) {
  short return_value = 0;
  short saw_forbid = 0;

  return_value = handler_email(flag, cat_id, prt);
  if (return_value == ERROR)
    return return_value;
  else if (return_value == FORBID_VIOLATION)
    saw_forbid = 1;

  return_value = handler_phone(flag, cat_id, prt);

  if (saw_forbid == 1 && return_value != ERROR)
    return FORBID_VIOLATION;
  return return_value;
}
