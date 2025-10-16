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

    char *left = tmp - 1;
    if (isalnum((unsigned char)*left)) {
      tmp++;
      continue;
    }

    char *start = tmp + 1;
    if (!isalnum((unsigned char)*start)) {
      tmp++;
      continue;
    }

    char *end = start;
    while (*end && *end != ' ' && *end != '\r' && *end != '\t' && *end != '\n')
      end++;

    while (end > start && (end[-1] == ',' || end[-1] == '.' || end[-1] == ';' ||
                           end[-1] == ':'))
      end--;

    found = 1;
    if (process_match_and_act(flag, cat_id, prt, left, end, &saw_forbid) ==
        ERROR)
      return ERROR;

    tmp = end;
  }

  static const char *PREFIXES[] = {
      "t.me/",           "telegram.me/",  "x.com/",           "instagram.com/",
      "github.com/",     "reddit.com/u/", "reddit.com/user/", "threads.net/",
      "linkedin.com/in/"};
  const size_t N = sizeof(PREFIXES) / sizeof(PREFIXES[0]);

  for (size_t i = 0; i < N; ++i) {
    char *p = prt->buf;
    size_t plen = strlen(PREFIXES[i]);

    while (*p) {
      const char *normalized = normalize_prefix_start(p);
      char *f = strstr(normalized, PREFIXES[i]);
      if (!f)
        break;

      char *user = f + (ptrdiff_t)plen;
      if (!isalnum((unsigned char)*user) && *user != '_') {
        p = f + 1;
        continue;
      }

      char *end = scan_handle_end(user);
      if (end > user) {
        found = 1;
        if (process_match_and_act(flag, cat_id, prt, user, end, &saw_forbid) ==
            ERROR)
          return ERROR;
      }

      p = end;
    }
  }

  char *p = prt->buf;
  while ((p = strstr(p, "u/")) != NULL) {
    if (p > prt->buf && isalnum((unsigned char)p[-1])) {
      p += 2;
      continue;
    }
    char *user = p + 2;
    if (!isalnum((unsigned char)*user)) {
      p += 2;
      continue;
    }

    char *end = scan_handle_end(user);
    if (end > user) {
      found = 1;
      if (process_match_and_act(flag, cat_id, prt, user, end, &saw_forbid) ==
          ERROR)
        return ERROR;
    }
    p = end;
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

  if (found && saw_forbid)
    return FORBID_VIOLATION;
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
