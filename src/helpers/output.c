#include "detector_result.h"
#include "eval.h"
#include "parser.h"
#include "runtime.h"
#include <stdio.h>
#include <string.h>

static void indent(int n) {
  while (n--) {
    fputs("  ", stdout);
  }
}

static const char *action_name_from_idx(int action_idx) {
  switch (action_idx) {
  case COUNTS_FORBID:
    return "forbid";
  case COUNTS_REDACT:
    return "redact";
  case COUNTS_APPEND:
    return "append";
  default:
    return "unknown";
  }
}

static const char *backend_name(DetectorBackend b) {
  switch (b) {
  case DET_BACKEND_DETERMINISTIC:
    return "deterministic";
  case DET_BACKEND_HYBRID:
    return "hybrid";
  case DET_BACKEND_PROBABILISTIC:
    return "probabilistic";
  default:
    return "unknown";
  }
}

static void print_escaped(const char *s, int len) {
  putchar('"');
  if (!s || len <= 0) {
    putchar('"');
    return;
  }
  for (int i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
    case '\n':
      fputs("\\n", stdout);
      break;
    case '\r':
      fputs("\\r", stdout);
      break;
    case '\t':
      fputs("\\t", stdout);
      break;
    case '\\':
      fputs("\\\\", stdout);
      break;
    case '"':
      fputs("\\\"", stdout);
      break;
    default:
      if (c >= 32 && c < 127) {
        putchar(c);
      } else {
        printf("\\x%02X", c);
      }
    }
  }
  putchar('"');
}

static const char *tag_name(Tag t) {
  switch (t) {
  case N_I:
    return "N_I";
  case N_POLICY:
    return "N_POLICY";
  case N_FORBID:
    return "N_FORBID";
  case N_REDACT:
    return "N_REDACT";
  case N_TEXT:
    return "N_TEXT";
  case N_APPEND:
    return "N_APPEND";
  default:
    return "?";
  }
}

static void dump_strview(StrView s, int depth, const char *label) {
  indent(depth);
  printf("%s{ ptr=%p, len=%d, text=", label, (void *)s.ptr, s.len);
  print_escaped(s.ptr, s.len);
  printf(" }\n");
}

static void dump_token(Token t, int depth, const char *label) {
  indent(depth);
  printf("%s{ type=%d, start=%p, len=%d, text=", label, (int)t.type,
         (void *)t.start, t.len);
  print_escaped(t.start, t.len);
  printf(" }\n");
}

static void dump_identifier(const Identifier *id, int depth,
                            const char *label) {
  indent(depth);
  printf("%s{\n", label);
  dump_token(id->tk, depth + 1, "tk=");
  dump_strview(id->value, depth + 1, "value=");
  indent(depth);
  printf("}\n");
}

static void dump_param(const Param *id, int depth, const char *label) {
  indent(depth);
  printf("%s{\n", label);
  dump_token(id->tk, depth + 1, "tk=");
  dump_strview(id->value, depth + 1, "value=");
  indent(depth);
  printf("}\n");
}

static void dump_id_array(const Identifier *ids, int n, int depth,
                          const char *label) {
  indent(depth);
  printf("%s(len=%d) [\n", label, n);
  for (int i = 0; i < n; ++i) {
    indent(depth + 1);
    printf("#%d @%p\n", i, (const void *)&ids[i]);
    dump_identifier(&ids[i], depth + 2, "id=");
  }
  indent(depth);
  printf("]\n");
}

static void dump_pair(const Pair *pr, int depth, const char *label) {
  indent(depth);
  if (!pr) {
    printf("%sNULL\n", label);
    return;
  }
  printf("%s{\n", label);
  dump_identifier(&pr->i, depth + 1, "i=");
  dump_strview(pr->value, depth + 1, "value=");
  indent(depth);
  printf("}\n");
}

static void dump_pair_array(const Pair *pairs, int n, int depth,
                            const char *label) {
  indent(depth);
  printf("%s(len=%d) [\n", label, n);
  for (int i = 0; i < n; ++i) {
    indent(depth + 1);
    printf("#%d @%p\n", i, (const void *)&pairs[i]);
    dump_pair(&pairs[i], depth + 2, "pair=");
  }
  indent(depth);
  printf("]\n");
}

static void dump_node(const Node *n, int depth, const char *label) {
  if (!n) {
    indent(depth);
    printf("%sNULL\n", label);
    return;
  }

  indent(depth);
  printf("%s{\n", label);
  indent(depth + 1);
  printf("tag=%s\n", tag_name(n->tag));
  dump_token(n->tk, depth + 1, "tk=");

  switch (n->tag) {
  case N_FORBID:
    indent(depth + 1);
    printf("num_ids=%d\n", n->num_ids);
    dump_id_array(n->forbid.ids, n->num_ids, depth + 1, "forbid.ids=");
    break;

  case N_REDACT:
    indent(depth + 1);
    printf("num_pairs=%d\n", n->num_ids);
    dump_pair_array(n->pair, n->num_ids, depth + 1, "redact.pairs=");
    break;

  case N_APPEND:
    indent(depth + 1);
    printf("num_pairs=%d\n", n->num_ids);
    dump_pair_array(n->pair, n->num_ids, depth + 1, "append.pairs=");
    break;

  default:
    break;
  }

  indent(depth);
  printf("}\n");
}

static void dump_policy(const Policy *pl, int depth, const char *label) {
  if (!pl) {
    indent(depth);
    printf("%sNULL\n", label);
    return;
  }

  indent(depth);
  printf("%s{\n", label);
  dump_identifier(&pl->name, depth + 1, "name=");
  indent(depth + 1);
  printf("nparams=%d\n", pl->nparams);
  for (int i = 0; i < pl->nparams; ++i) {
    dump_param(&pl->params[i], depth + 1, "param=");
  }

  dump_node(&pl->forbid, depth + 1, "forbid=");
  dump_node(&pl->redact, depth + 1, "redact=");
  dump_node(&pl->append, depth + 1, "append=");
  indent(depth);
  printf("}\n");
}

void dump_program(const Program *pr) {
  if (!pr) {
    printf("Program=NULL\n");
    return;
  }
  printf("Program{\n");
  printf("  count=%d, cap=%d, stms=%p\n", pr->count, pr->cap, (void *)pr->stms);
  for (int i = 0; i < pr->count; ++i) {
    dump_policy(&pr->stms[i], 1, "policy=");
  }
  printf("}\n");
}

char *long_to_binary(unsigned long k)

{
  static char c[65];
  c[0] = '\0';

  unsigned long val;
  for (val = 1UL << (sizeof(unsigned long) * 8 - 1); val > 0; val >>= 1) {
    strcat(c, ((k & val) == val) ? "1" : "0");
  }
  return c;
}

static const char *cat_name(int id) {
  switch (id) {
  case 0:
    return "privacy";
  case 1:
    return "personal_id";
  case 2:
    return "phone";
  case 3:
    return "email";
  case 4:
    return "address";
  case 5:
    return "financial_id";
  case 6:
    return "credit_card";
  case 7:
    return "bank_account";
  case 8:
    return "tax_id";
  case 9:
    return "online_id";
  case 10:
    return "ip";
  case 11:
    return "handle";
  case 12:
    return "device_id";
  case 13:
    return "location";
  case 15:
    return "non-maleficence";
  case 16:
    return "discrimination";
  case 18:
    return "self_harm";
  case 19:
    return "dangerous_instructions";
  case 21:
    return "medical_risk";

  default:
    return "unknown";
  }
}

static const char *act_label(int act) {
  return (act == 0)   ? "forbid"
         : (act == 1) ? "redact"
         : (act == 2) ? "append"
                      : "act?";
}

void print_debug_summary(const PolicyRunTime *prt) {
  if (!prt->debug)
    return;

  printf("[DEBUG] ");
  for (int act = 0; act < 3; ++act) {
    if (prt->total_by_action[act] == 0)
      continue;

    printf("%s: ", act_label(act));
    int first = 1;
    for (int id = 0; id < MAX_CATS; ++id) {
      int n = prt->counts[act][id];
      if (n > 0) {
        if (!first)
          printf(", ");
        printf("%s (%d)", cat_name(id), n);
        first = 0;
      }
    }
    putchar('\n');
  }
}

void print_eval_json(PolicyRunTime *prt, const DetectorLog *det_logs,
                     size_t det_len, const char *mode, int return_code) {
  const char *status = (return_code == FORBID_VIOLATION) ? "FORBIDDEN"
                       : (return_code == OK)             ? "OK"
                                                         : "ERROR";

  printf("{\n");
  printf("  \"mode\": \"%s\",\n", mode);
  printf("  \"status\": \"%s\",\n", status);
  printf("  \"return_code\": %d,\n", return_code);

  if (prt->buf && (prt->debug || return_code == OK)) {
    printf("  \"transformed_text\": \"%s\",\n", prt->buf);
  }

  if (prt->debug) {
    printf("  \"actions_applied\": [\n");
    int first = 1;

    for (int act = 0; act < 3; act++) {
      for (int cat = 0; cat < MAX_CATS; cat++) {
        int count = prt->counts[act][cat];
        if (count > 0) {
          if (!first)
            printf(",\n");
          printf("    {\"action\":\"%s\",\"evaluated\":\"%s\",\"count\":%d}",
                 act_label(act), cat_name(cat), count);
          first = 0;
        }
      }
    }

    if (!first)
      printf("\n");
    printf("  ],\n");

    printf("  \"detectors\": [");

    for (size_t k = 0; k < det_len; k++) {
      const DetectorLog *dl = &det_logs[k];
      const DetectorResult *d = &dl->dr;

      if (k > 0)
        printf(",");

      printf("\n    {"
             "\"action\":\"%s\","
             "\"category\":\"%s\","
             "\"cat_id\":%d,"
             "\"backend\":\"%s\","
             "\"score\":%.6f,"
             "\"threshold\":%.6f,"
             "\"matched\":%s"
             "}",
             action_name_from_idx(dl->action_idx), cat_name(d->cat_id),
             d->cat_id, backend_name(d->backend), d->score, d->threshold,
             d->matched ? "true" : "false");
    }

    if (det_len > 0)
      printf("\n");
    printf("  ],\n");

    printf("  \"totals\": {\"forbid\": %d, \"redact\": %d, \"append\": %d},\n",
           prt->total_by_action[0], prt->total_by_action[1],
           prt->total_by_action[2]);
  }

  printf("  \"debug\": {\"enabled\": %s}\n", prt->debug ? "true" : "false");
  printf("}\n");
}
