#include "../../eval.h"
#include "../helpers/helper.h"
#include "runtime.h"
#include "sh.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int start;
  int end;
  int bitmask;
} Type;

static const char *const L_LIFE[] = {"life"};
static const char *const L_ENDLIFE_V[] = {"end", "finish", "take"};
static const char *const L_REPORT_VB[] = {
    "say",  "says",  "said",   "tell",    "tells",
    "told", "quote", "quoted", "suggest", "suggested"};

enum {
  CL_ENC = 1 << 0,
  CL_TARGET = 1 << 1,
  CL_2P = 1 << 2,
  CL_IMP = 1 << 3,
  CL_NEG = 1 << 4,
  CL_SUPPORT = 1 << 5,
  CL_REPORT = 1 << 6,
  CL_LIFE = 1 << 7,
  CL_ENDLIFE_V = 1 << 8,
  CL_REPORT_VB = 1 << 9,
  CL_AGGR = 1 << 10,
};

static int token_in_list(const char *t, const char *const *list, size_t n) {
  for (size_t i = 0; i < n; ++i)
    if (strcmp(t, list[i]) == 0)
      return 1;
  return 0;
}

static void collapse_alnum_lower(const char *in, char *out, size_t cap) {
  size_t k = 0;
  for (size_t i = 0; in[i] && k + 1 < cap; ++i) {
    unsigned char c = (unsigned char)in[i];
    if (isalnum(c))
      out[k++] = (char)tolower(c);
  }
  out[k] = '\0';
}

static int classify_token(const char *t, int aggr) {
  int mask = 0;
  if (token_in_list(t, L_ENC, sizeof(L_ENC) / sizeof(L_ENC[0])))
    mask |= CL_ENC;
  if (token_in_list(t, L_TARGET, sizeof(L_TARGET) / sizeof(L_TARGET[0])))
    mask |= CL_TARGET;
  if (token_in_list(t, L_2P, sizeof(L_2P) / sizeof(L_2P[0])))
    mask |= CL_2P;
  if (token_in_list(t, L_IMP, sizeof(L_IMP) / sizeof(L_IMP[0])))
    mask |= CL_IMP;
  if (token_in_list(t, L_NEG, sizeof(L_NEG) / sizeof(L_NEG[0])))
    mask |= CL_NEG;
  if (token_in_list(t, L_SUPPORT, sizeof(L_SUPPORT) / sizeof(L_SUPPORT[0])))
    mask |= CL_SUPPORT;
  if (token_in_list(t, L_REPORT, sizeof(L_REPORT) / sizeof(L_REPORT[0])))
    mask |= CL_REPORT;
  if (token_in_list(t, L_LIFE, sizeof(L_LIFE) / sizeof(L_LIFE[0])))
    mask |= CL_LIFE;
  if (token_in_list(t, L_ENDLIFE_V,
                    sizeof(L_ENDLIFE_V) / sizeof(L_ENDLIFE_V[0])))
    mask |= CL_ENDLIFE_V;
  if (token_in_list(t, L_REPORT_VB,
                    sizeof(L_REPORT_VB) / sizeof(L_REPORT_VB[0])))
    mask |= CL_REPORT_VB;

  if (aggr) {
    if (token_in_list(t, L_2P_AGGR, sizeof(L_2P_AGGR) / sizeof(L_2P_AGGR[0])))
      mask |= CL_2P;
    if (token_in_list(t, L_IMP_AGGR,
                      sizeof(L_IMP_AGGR) / sizeof(L_IMP_AGGR[0])))
      mask |= CL_IMP;

    char collapsed[64];
    collapse_alnum_lower(t, collapsed, sizeof(collapsed));
    if (token_in_list(collapsed, L_ENC_AGGR,
                      sizeof(L_ENC_AGGR) / sizeof(L_ENC_AGGR[0]))) {
      mask |= CL_AGGR;
      if (strcmp(collapsed, "take") == 0)
        mask |= CL_ENDLIFE_V;
      if (strcmp(collapsed, "life") == 0)
        mask |= CL_LIFE;
    }
  }
  return mask;
}

static int tokenize_ascii(const char *s, Type *out, int max_tok, int aggr) {
  int n_tokens = 0;
  int i = 0;

  while (s[i]) {
    while (s[i] && !isalnum((unsigned char)s[i]) && s[i] != '\'' && s[i] != '-')
      i++;

    if (!s[i])
      break;

    int tk_len = 0;
    int start = i;
    char buf[64];

    while (s[i] &&
           (isalnum((unsigned char)s[i]) || s[i] == '\'' || s[i] == '-')) {
      char c = (char)tolower((unsigned char)s[i]);
      if (tk_len < (int)sizeof(buf) - 1)
        buf[tk_len++] = c;
      i++;
    }
    buf[tk_len] = '\0';
    int end = i;

    if (n_tokens < max_tok) {
      out[n_tokens].start = start;
      out[n_tokens].end = end;
      out[n_tokens].bitmask = classify_token(buf, aggr);
      n_tokens++;
    } else
      break;
  }

  return n_tokens;
}

static inline int is_sent_end_char(char c) {
  return (c == '.' || c == '!' || c == '?' || c == '\n');
}

static int sentence_end_tok(const char *buf, Type *T, int n_tks, int start_tk) {
  if (start_tk >= n_tks)
    return start_tk;

  int last_end = T[start_tk].end;

  for (int i = start_tk; i < n_tks; i++) {
    for (int p = last_end; p < T[i].start; p++) {
      if (is_sent_end_char(buf[p]))
        return i;
    }
    last_end = T[i].end;
  }

  int tail = (int)strlen(buf);
  for (int p = last_end; p < tail; p++) {
    if (is_sent_end_char(buf[p]))
      return n_tks;
  }

  return n_tks;
}

static int min_dist_between(const Type *T, int a, int b, int mask_a,
                            int mask_b) {
  int best = 1e9;
  for (int i = a; i < b; i++)
    if (T[i].bitmask & mask_a)
      for (int j = a; j < b; j++)
        if (T[j].bitmask & mask_b) {
          int d = (i > j) ? (i - j) : (j - i);
          if (best > d)
            best = d;
        }
  return best;
}

static int score_window(Type *T, int a, int b, int aggr) {
  int have_enc = 0;
  int have_target = 0;
  int have_sec_p = 0;
  int have_imp = 0;
  int have_negative = 0;
  int have_support = 0;
  int have_report = 0;
  int have_rv = 0;
  int have_life = 0;
  int have_ev = 0;
  int have_aggr = 0;

  for (int i = a; i < b; i++) {
    int mask = T[i].bitmask;
    have_enc |= (mask & CL_ENC) ? 1 : 0;
    have_target |= (mask & CL_TARGET) ? 1 : 0;
    have_sec_p |= (mask & CL_2P) ? 1 : 0;
    have_imp |= (mask & CL_IMP) ? 1 : 0;
    have_negative |= (mask & CL_NEG) ? 1 : 0;
    have_support |= (mask & CL_SUPPORT) ? 1 : 0;
    have_report |= (mask & CL_REPORT) ? 1 : 0;
    have_rv |= (mask & CL_REPORT_VB) ? 1 : 0;
    have_life |= (mask & CL_LIFE) ? 1 : 0;
    have_ev |= (mask & CL_ENDLIFE_V) ? 1 : 0;
    have_aggr |= (mask & CL_AGGR) ? 1 : 0;
  }

  int score = 0;
  if (have_enc && (have_target || have_sec_p))
    score += 3;
  if (have_aggr)
    score += 4;
  if (have_imp)
    score += 2;
  if (have_sec_p)
    score += 1;
  if (have_negative)
    score -= 1;
  if (have_support)
    score -= 2;
  if (have_report)
    score -= 2;

  const int K1 = aggr ? 10 : 8;
  const int K2 = aggr ? 8 : 6;

  // micropatterns for proximity boost
  int d1 = min_dist_between(T, a, b, CL_ENC, (CL_TARGET | CL_2P));
  if (d1 <= K1)
    score += 2;

  if (have_ev && have_life) {
    int d2 = min_dist_between(T, a, b, CL_ENDLIFE_V, CL_LIFE);
    if (d2 <= K2)
      score += 2;
  }

  if (have_rv && !have_imp)
    score--;

  return score;
}

int handler_self_harm(int flag, int cat_id, PolicyRunTime *prt) {
  const int W_SIZE = 12;
  const int THRESHOLD = 4;
  const int MAX_TKS = 2048;

  Type *t = (Type *)malloc(sizeof(Type) * MAX_TKS);
  if (!t)
    return ERROR;

  int n_tks = tokenize_ascii(prt->buf, t, MAX_TKS, prt->aggr);
  if (n_tks <= 0) {
    free(t);
    return OK;
  }

  int found = 0;
  int saw_forbid = 0;
  int best_a = 0;
  int best_b = 0;
  int best_score = -999;

  for (int start = 0; start < n_tks;) {
    int end = sentence_end_tok(prt->buf, t, n_tks, start);

    int sent_exempt = 0;
    for (int k = start; k < end; k++) {
      if (t[k].bitmask & (CL_SUPPORT | CL_REPORT | CL_NEG)) {
        sent_exempt = 1;
        break;
      }
    }

    int best_s_score = -999, best_s_a = start, best_s_b = start;
    for (int i = start; i < end;) {
      int j = i + W_SIZE;
      if (j > end)
        j = end;
      int score = score_window(t, i, j, prt->aggr);
      if (score >= THRESHOLD) {
        if (score > best_s_score) {
          best_s_score = score;
          best_s_a = i;
          best_s_b = j;
        }
        i = j;
      } else {
        i++;
      }
    }

    if (!sent_exempt && best_s_score >= THRESHOLD) {
      found = 1;
      if (best_s_score > best_score) {
        best_score = best_s_score;
        best_a = best_s_a;
        best_b = best_s_b;
      }
    }

    start = (end > start ? end : start + 1);
  }

  if (!found) {
    free(t);
    return OK;
  }

  int act = action_from_flag(flag);
  if (act >= 0) {
    prt->counts[act][cat_id] += 1;
    prt->total_by_action[act] += 1;
  }

  switch (flag) {
  case FORBID_FLAG:
    saw_forbid = 1;
    break;
  case REDACT_FLAG: {
    StrView mask = prt->mask_redact[cat_id];
    char c = (mask.ptr && mask.len) ? mask.ptr[0] : '*';
    int start = t[best_a].start;
    int end = t[best_b - 1].end;
    if (start < end && start >= 0 && end <= (int)strlen(prt->buf))
      memset(prt->buf + start, c, (size_t)(end - start));
    break;
  }
  case APPEND_FLAG:
    break;

  default:
    free(t);
    return ERROR;
  }

  if (found && saw_forbid) {
    free(t);
    return FORBID_VIOLATION;
  }

  if (found && flag == APPEND_FLAG) {
    StrView app = prt->append_string[cat_id];
    if (app.ptr && app.len > 0) {
      size_t cur_len = strlen(prt->buf);
      size_t need = cur_len + 1 + (size_t)app.len + 1;
      if (!ensure_cap(prt, need)) {
        free(t);
        return ERROR;
      }
      prt->buf[cur_len] = ' ';
      memcpy(prt->buf + cur_len + 1, app.ptr, (size_t)app.len);
      prt->buf[cur_len + 1 + app.len] = '\0';
    }
  }

  free(t);
  return OK;
}
