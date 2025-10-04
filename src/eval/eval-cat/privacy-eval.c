#include "../eval.h"
#include "helpers/helper.h"
#include "parser.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ensure_cap(PolicyRunTime *prt, size_t need) {
  if (prt->buf && prt->buf_cap >= need)
    return 1;
  size_t cap = prt->buf_cap ? prt->buf_cap : 64;
  while (cap < need)
    cap *= 2;
  char *new_block = (char *)realloc(prt->buf, cap);
  if (!new_block)
    return 0;
  prt->buf = new_block;
  prt->buf_cap = cap;
  return 1;
}

int handler_email(int flag, int cat_id, PolicyRunTime *prt) {
  char *tmp = prt->buf;
  int found = 0;

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
      left_segment--; // decrement pointer one step at a time
    }

    left_segment++; // increment one value to the pointer because the late check
                    // ended after the correct pos

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
      return FORBID_VIOLATION;
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
