#include "parser.h"
#include <ctype.h>
#include <stdio.h>

/* ---------- helpers ---------- */

static void indent(int n) {
  while (n--)
    fputs("  ", stdout);
}

/* prints a string slice with escapes, without assuming NUL-termination */
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

/* optional: name your enums if you like; fallback prints integer */
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

/* flat Identifier array with count */
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
    dump_IdArray(n->forbid.ids, n->num_ids, depth + 1, "forbid.ids=");
    break;

  case N_REDACT:
    dump_IdArray(n->redact.ids, n->num_ids, depth + 1, "redact.ids=");
    break;

  case N_APPEND: {
    dump_IdArray(n->append.ids, n->num_ids, depth + 1, "append.ids=");
    const char *txt =
        (n->append.text && *n->append.text) ? *n->append.text : NULL;
    indent(depth + 1);
    printf("append.text_ptr=%p, text=",
           (void *)(n->append.text ? *n->append.text : NULL));
    if (txt) {
      /* print C string with escapes */
      fputc('"', stdout);
      for (const unsigned char *p = (const unsigned char *)txt; *p; ++p) {
        unsigned char c = *p;
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
      fputc('"', stdout);
      fputc('\n', stdout);
    } else {
      printf("NULL\n");
    }
    break;
  }

  default:
    /* other tags: nothing additional in union */
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
  for (int i = 0; i < pl->nparams; ++i) {
    dump_Identifier(&pl->params[i], depth + 1, "param=");
  }
  dump_Node(&pl->forbid, depth + 1,
            "forbid="); /* embedded Node → pass address */
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
  for (int i = 0; i < pr->count; ++i) {
    dump_Policy(&pr->stms[i], 1, "policy=");
  }
  printf("}\n");
}
