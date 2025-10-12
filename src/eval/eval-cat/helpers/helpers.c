#include "../../eval.h"
#include "helper.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int action_from_flag(int flag) {
  return (flag == FORBID_FLAG)   ? 0
         : (flag == REDACT_FLAG) ? 1
         : (flag == APPEND_FLAG) ? 2
                                 : -1;
}

int ensure_cap(PolicyRunTime *prt, size_t need) {
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

int process_match_and_act(int flag, int cat_id, PolicyRunTime *prt, char *beg,
                          char *end, short *saw_forbid) {
  int act = action_from_flag(flag);
  if (act >= 0) {
    prt->counts[act][cat_id] += 1;
    prt->total_by_action[act] += 1;
  }

  switch (flag) {
  case FORBID_FLAG:
    (*saw_forbid)++;
    break;
  case REDACT_FLAG: {
    StrView mask = prt->mask_redact[cat_id];
    char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';
    size_t n = (size_t)(end - beg);
    memset(beg, c, n);
    break;
  }
  case APPEND_FLAG:
    break;
  default:
    return ERROR;
  }
  return OK;
}

int is_handle_char(unsigned char c) {
  return (isalnum(c) || c == '_' || c == '.' || c == '-');
}

char *scan_handle_end(char *p) {
  while (*p && is_handle_char((unsigned char)*p))
    p++;
  return p;
}
