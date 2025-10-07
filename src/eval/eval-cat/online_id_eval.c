#define PCRE2_CODE_UNIT_WIDTH 8
#include "../eval.h"
#include "helpers/helper.h"
#include "parser.h"
#include "runtime.h"
#include <ctype.h>
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int handler_ip(int flag, int cat_id, PolicyRunTime *prt) {
  short found = 0;
  short saw_forbid = 0;
  char *tmp = prt->buf;

  while (*tmp) {
    if (!isdigit((unsigned char)*tmp)) {
      tmp++;
      continue;
    }

    char *start = tmp;
    int n_octets = 0;
    int valid = 1;

    while (n_octets < 4) {
      int val = 0;
      int digits = 0;

      while (isdigit(*tmp)) {
        val = val * 10 + (*tmp - '0');
        digits++;
        tmp++;
      }

      if (digits < 1 || digits > 3 || val > 255) {
        valid = 0;
        break;
      }

      n_octets++;
      if (n_octets == 4)
        break;
      if (*tmp != '.') {
        valid = 0;
        break;
      }
      tmp++;
    }

    if (valid && n_octets == 4) {
      char after = *tmp;
      char before = start > prt->buf ? start[-1] : ' ';

      if (!isdigit(before) && before != '.' && before != ':' &&
          !isdigit(after) && after != '.' && after != ':') {

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
          memset(start, c, (size_t)(tmp - start));
          break;
        }
        case APPEND_FLAG:
          break;
        default:
          return ERROR;
        }

        continue;
      }
    }

    tmp = start + 1;
  }

  if (found && saw_forbid > 0)
    return FORBID_VIOLATION;

  if (found && flag == APPEND_FLAG) {
    StrView app = prt->append_string[cat_id];
    if (app.ptr && app.len > 0) {
      size_t cur = strlen(prt->buf);
      size_t need = cur + 1 + (size_t)app.len + 1;
      if (!ensure_cap(prt, need))
        return ERROR;
      prt->buf[cur] = ' ';
      memcpy(prt->buf + cur + 1, app.ptr, (size_t)app.len);
      prt->buf[cur + 1 + app.len] = '\0';
    }
  }

  return OK;
}

// int handler_sm_handle(int flag, int cat_id, PolicyRunTime *prt) { return 0; }
