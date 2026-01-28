#define _POSIX_C_SOURCE 200809L
#define PCRE2_CODE_UNIT_WIDTH 8
#include "../../eval.h"
#include "../helpers/helper.h"
#include "runtime.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcre2.h>

static int luhn_ok(const char *digits) {
  int sum = 0;
  int alt = 0;
  int n = (int)strlen(digits);

  for (int i = n - 1; i >= 0; --i) {
    unsigned char c = (unsigned char)digits[i];
    if (c < '0' || c > '9')
      return 0;

    int d = (int)(c - '0');
    if (alt) {
      d *= 2;
      if (d > 9)
        d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return (sum % 10) == 0;
}

static int extract_digits(const char *src, size_t s, size_t e, char *out,
                          size_t out_cap) {
  size_t k = 0;
  for (size_t i = s; i < e; i++) {
    unsigned char c = (unsigned char)src[i];
    if (isdigit(c)) {
      if (k + 1 >= out_cap)
        return 0;
      out[k++] = (char)c;
    }
  }
  out[k] = '\0';
  return 1;
}

typedef struct {
  const char *name;
  pcre2_code *re;
} BrandRe;

static const char *BRAND_PATTERNS[][2] = {
    {"banese", "^(636117|637473|637470|636659|637472)[0-9]{10,12}$"},
    {"elo",
     "^(401178|401179|431274|438935|451416|457393|457631|457632|504175|627780|"
     "636297|636368|(506699|5067[0-6]\\d|50677[0-8])|(50900\\d|5090[1-9]\\d|"
     "509[1-9]\\d{2})|65003[1-3]|(65003[5-9]|65004\\d|65005[0-1])|(65040[5-9]|"
     "6504[1-3]\\d)|(65048[5-9]|65049\\d|6505[0-2]\\d|65053[0-8])|(65054[1-9]|"
     "6505[5-8]\\d|65059[0-8])|(65070\\d|65071[0-8])|65072[0-7]|(65090[1-9]|"
     "65091\\d|650920)|(65165[2-9]|6516[6-7]\\d)|(65500\\d|65501\\d)|(65502[1-"
     "9]|6550[3-4]\\d|65505[0-8]))[0-9]{10,12}$"},
    {"cabal", "^(604324|604330|604337|604203|604338)[0-9]{10,12}$"},
    {"softnex", "^610800"},
    {"diners", "^3(?:0[0-5]|[68][0-9])[0-9]{11}$"},
    {"discover", "^6(?:011|5[0-9]{2}|4[4-9][0-9]{1}|(22(12[6-9]|1[3-9][0-9]|[2-"
                 "8][0-9]{2}|9[01][0-9]|92[0-5]$)[0-9]{10}$))[0-9]{12}$"},
    {"hipercard", "^(606282|637095|3841[046]0)[0-9]{10}$"},
    {"amex", "^3[47][0-9]{13}$"},
    {"aura", "^5078[0-9]{12,15}$"},
    {"codensa", "^(870055|590712|529448)[0-9]{10}$"},
    {"master", "^"
               "(5[1-5][0-9]{14}"
               "|2221[0-9]{12}"
               "|222[2-9][0-9]{12}"
               "|22[3-9][0-9]{13}"
               "|2[3-6][0-9]{14}"
               "|27[01][0-9]{13}"
               "|2720[0-9]{12}"
               "|5[06789][0-9]{14}"
               "|600[689][0-9]{12}"
               "|602[468][0-9]{12}"
               "|603[0-9]{13}"
               "|604[69][0-9]{12}"
               "|605[045][0-9]{12}"
               "|606[234][0-9]{12}"
               "|6095[0-9]{12}"
               "|6220[0-9]{12}"
               "|627[389][0-9]{12}"
               "|628[01][0-9]{12}"
               "|6305[0-9]{12}"
               "|631[06][0-9]{12}"
               "|636[13678][0-9]{12}"
               "|637[1256][0-9]{12}"
               "|6381[0-9]{12}"
               "|639[2-7][0-9]{12}"
               "|6602[0-9]{12}"
               "|662[269][0-9]{12}"
               "|6640[0-9]{12}"
               "|665[49][0-9]{12}"
               "|666[2478][0-9]{12}"
               "|667[79][0-9]{12}"
               "|668[03569][0-9]{12}"
               "|6690[0-9]{12}"
               "|671[45][0-9]{12}"
               "|6748[0-9]{12}"
               "|6777[0-9]{12}"
               "|678[37][0-9]{12}"
               "|679[29][0-9]{12}"
               "|681[056][0-9]{12}"
               "|684[37][0-9]{12}"
               "|6874[0-9]{12}"
               "|68[589]0[0-9]{12}"
               ")$"},
    {"visa", "^4[0-9]{12}(?:[0-9]{3})?$"},
};

static int brand_match_digits_only(const char *digits) {
  static int ready = 0;
  static BrandRe brands[64];
  static size_t nbrands = 0;

  if (!ready) {
    PCRE2_SIZE erroff = 0;
    int errcode = 0;

    nbrands = sizeof(BRAND_PATTERNS) / sizeof(BRAND_PATTERNS[0]);
    if (nbrands > (sizeof(brands) / sizeof(brands[0])))
      return 0;

    for (size_t i = 0; i < nbrands; i++) {
      brands[i].name = BRAND_PATTERNS[i][0];
      const char *pat = BRAND_PATTERNS[i][1];

      brands[i].re = pcre2_compile((PCRE2_SPTR)pat, PCRE2_ZERO_TERMINATED, 0,
                                   &errcode, &erroff, NULL);
      if (!brands[i].re) {
        return -1;
      }
    }
    ready = 1;
  }

  pcre2_match_data *md = pcre2_match_data_create(8, NULL);
  if (!md)
    return -1;

  size_t dlen = strlen(digits);
  for (size_t i = 0; i < nbrands; i++) {
    int rc =
        pcre2_match(brands[i].re, (PCRE2_SPTR)digits, dlen, 0, 0, md, NULL);
    if (rc >= 0) {
      pcre2_match_data_free(md);
      return 1;
    }
  }

  pcre2_match_data_free(md);
  return 0;
}

int handler_card(int flag, int cat_id, PolicyRunTime *prt) {
  static pcre2_code *re = NULL;
  static int re_ready = 0;

  short saw_forbid = 0;

  if (!prt || !prt->buf)
    return ERROR;

  if (!re_ready) {
    PCRE2_SIZE erroff = 0;
    int errcode = 0;

    PCRE2_SPTR pat = (PCRE2_SPTR) "(?:\\d[ -]?){13,23}\\d";

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
        (isalnum((unsigned char)prt->buf[s - 1]) ||
         isalnum((unsigned char)prt->buf[e]))) {
      off = e;
      continue;
    }

    char digits[64];
    if (!extract_digits(prt->buf, s, e, digits, sizeof(digits))) {
      off = e;
      continue;
    }

    size_t dlen = strlen(digits);
    if (dlen < 13 || dlen > 19) {
      off = e;
      continue;
    }

    if (!luhn_ok(digits)) {
      off = e;
      continue;
    }

    int bm = brand_match_digits_only(digits);
    if (bm < 0) {
      pcre2_match_data_free(md);
      return ERROR;
    }
    if (bm == 0) {
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
      pcre2_match_data_free(md);
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
