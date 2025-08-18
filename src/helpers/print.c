#include "parser.h"
#include <ctype.h>
#include <stdio.h>

/* ---------- helpers ---------- */

static void indent(int n) {
  while (n--)
    fputs("  ", stdout);
}

/* print a string slice with escapes, without assuming NUL-termination */
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
      if (c >= 32 && c < 127)
        putchar(c);
      else
        printf("\\x%02X", c);
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

/* ---------- dumps for your structs ---------- */

static void dump_StrView(StrView s, int depth, const char *label) {
  indent(depth);
  printf("%s{ ptr=%p, len=%d, text=", label, (void *)s.ptr, s.len);
  print_escaped(s.ptr, s.len);
  printf(" }\n");
}

static void dump_Token(Token t, int depth, const char *label) {
  indent(depth);
  printf("%s{ type=%d, start=%p, len=%d, text=", label, (int)t.type,
         (void *)t.start, t.len);
  print_escaped(t.start, t.len);
  printf(" }\n");
}

static void dump_Identifier(const Identifier *id, int depth,
                            const char *label) {
  indent(depth);
  printf("%s{\n", label);
  dump_Token(id->tk, depth + 1, "tk=");
  dump_StrView(id->value, depth + 1, "value=");
  indent(depth);
  printf("}\n");
}

static void dump_IdArray(const Identifier *ids, int n, int depth,
                         const char *label) {
  indent(depth);
  printf("%s(len=%d) [\n", label, n);
  for (int i = 0; i < n; ++i) {
    indent(depth + 1);
    printf("#%d @%p\n", i, (const void *)&ids[i]);
    dump_Identifier(&ids[i], depth + 2, "id=");
  }
  indent(depth);
  printf("]\n");
}

static void dump_Pair(const Pair *pr, int depth, const char *label) {
  indent(depth);
  if (!pr) {
    printf("%sNULL\n", label);
    return;
  }
  printf("%s{\n", label);
  dump_Identifier(&pr->i, depth + 1, "i=");
  dump_StrView(pr->value, depth + 1, "value=");
  indent(depth);
  printf("}\n");
}

static void dump_PairArray(const Pair *pairs, int n, int depth,
                           const char *label) {
  indent(depth);
  printf("%s(len=%d) [\n", label, n);
  for (int i = 0; i < n; ++i) {
    indent(depth + 1);
    printf("#%d @%p\n", i, (const void *)&pairs[i]);
    dump_Pair(&pairs[i], depth + 2, "pair=");
  }
  indent(depth);
  printf("]\n");
}

static void dump_Node(const Node *n, int depth, const char *label) {
  if (!n) {
    indent(depth);
    printf("%sNULL\n", label);
    return;
  }

  indent(depth);
  printf("%s{\n", label);
  indent(depth + 1);
  printf("tag=%s\n", tag_name(n->tag));
  dump_Token(n->tk, depth + 1, "tk=");

  switch (n->tag) {
  case N_FORBID:
    indent(depth + 1);
    printf("num_ids=%d\n", n->num_ids);
    dump_IdArray(n->forbid.ids, n->num_ids, depth + 1, "forbid.ids=");
    break;

  case N_REDACT:
    indent(depth + 1);
    printf("num_pairs=%d\n", n->num_ids);
    dump_PairArray(n->pair, n->num_ids, depth + 1, "redact.pairs=");
    break;

  case N_APPEND:
    indent(depth + 1);
    printf("num_pairs=%d\n", n->num_ids);
    dump_PairArray(n->pair, n->num_ids, depth + 1, "append.pairs=");
    break;

  default:
    /* nothing extra */
    break;
  }

  indent(depth);
  printf("}\n");
}

static void dump_Policy(const Policy *pl, int depth, const char *label) {
  if (!pl) {
    indent(depth);
    printf("%sNULL\n", label);
    return;
  }

  indent(depth);
  printf("%s{\n", label);
  dump_Identifier(&pl->name, depth + 1, "name=");
  indent(depth + 1);
  printf("nparams=%d\n", pl->nparams);
  for (int i = 0; i < pl->nparams; ++i)
    dump_Identifier(&pl->params[i], depth + 1, "param=");

  dump_Node(&pl->forbid, depth + 1, "forbid=");
  dump_Node(&pl->redact, depth + 1, "redact=");
  dump_Node(&pl->append, depth + 1, "append=");
  indent(depth);
  printf("}\n");
}

void dump_Program(const Program *pr) {
  if (!pr) {
    printf("Program=NULL\n");
    return;
  }
  printf("Program{\n");
  printf("  count=%d, cap=%d, stms=%p\n", pr->count, pr->cap, (void *)pr->stms);
  for (int i = 0; i < pr->count; ++i)
    dump_Policy(&pr->stms[i], 1, "policy=");
  printf("}\n");
}
