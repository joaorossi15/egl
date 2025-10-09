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

int handler_sm_handle(int flag, int cat_id, PolicyRunTime *prt) {
  char *tmp = prt->buf;
  int found = 0;
  short saw_forbid = 0;

  while ((tmp = strchr(tmp, '@')) != NULL) {
    if (tmp == prt->buf) {
      tmp++;
      continue;
    }

    char *left_segment = tmp - 1;

    if (isalnum((unsigned char)*left_segment)) {
      tmp++;
      continue;
    }

    char *right_segment = tmp + 1;
    if (!isalnum((unsigned char)*right_segment)) {
      tmp++;
      continue;
    }

    while (*right_segment && *right_segment != ' ' && *right_segment != '\0' &&
           *right_segment != '\r' && *right_segment != '\t') {
      right_segment++;
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

int handler_device_id(int flag, int cat_id, PolicyRunTime *prt) {
  short found = 0;
  short saw_forbid = 0;
  char *tmp = prt->buf;

  while (*tmp) {
    if (!isxdigit((unsigned char)*tmp)) {
      tmp++;
      continue;
    }

    char *start = tmp;
    int n_doubles = 0;
    int valid = 1;

    while (n_doubles < 6) {
      int digits = 0;

      while (isxdigit(*tmp)) {
        digits++;
        tmp++;
      }

      if (digits != 2) {
        valid = 0;
        break;
      }

      n_doubles++;
      if (n_doubles == 6)
        break;
      if (*tmp != '-' && *tmp != ':') {
        valid = 0;
        break;
      }
      tmp++;
    }

    if (valid && n_doubles == 6) {
      char after = *tmp;
      char before = start > prt->buf ? start[-1] : ' ';

      if (!isxdigit(before) && before != '-' && before != ':' &&
          !isxdigit(after) && after != '-' && after != ':') {

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

int handler_online_id(int flag, int cat_id, PolicyRunTime *prt) {
  short saw_forbid = 0;
  int return_value = 0;

  int (*handlers[3])(int, int, PolicyRunTime *) = {
      handler_ip, handler_sm_handle, handler_device_id};

  for (int i = 0; i < 3; i++) {
    return_value = handlers[i](flag, cat_id, prt);
    if (return_value == ERROR)
      return ERROR;
    if (return_value == FORBID_VIOLATION)
      saw_forbid = 1;
  }

  return saw_forbid ? FORBID_VIOLATION : return_value;
}
