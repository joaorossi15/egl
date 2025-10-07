#include "../../eval.h"
#include "helper.h"
#include <stdlib.h>

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
