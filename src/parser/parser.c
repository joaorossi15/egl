#include "parser.h"
#include "lexer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static Policy parse_policy(Parser *p, Token *tks);
static Node parse_node(Parser *p, Token *tks);
static Node parse_forbid(Parser *p, Token *tks);
// Node parse_append(Parser *p, Token *tks);
// Node parse_redact(Parser *p, Token *tks);

void init_program(Program *p) {
  p->cap = 64;
  p->count = 0;
  p->stms = malloc((size_t)p->cap * sizeof *p->stms);
}

void init_parser(Parser *p, Token *tks, int len) {
  p->cur_tk = tks[0];
  p->tks_len = len;
  p->peek_tk = (len > 1) ? tks[1] : tks[0];
  p->cur_pos = 0;
}

static inline StrView sv_from_token(const Token *t) {
  return (StrView){t->start, t->len};
}

static void next_token(Parser *p, Token *tks) {
  if (p->cur_pos + 1 >= p->tks_len) {
    p->cur_tk = tks[p->cur_pos];
    p->peek_tk = p->cur_tk;
    return;
  }
  p->cur_pos++;
  p->cur_tk = tks[p->cur_pos];
  p->peek_tk = (p->cur_pos + 1 < p->tks_len) ? tks[p->cur_pos + 1] : p->cur_tk;
}

void parse_program(Program *prog, Parser *p, Token *tks, int len) {
  init_program(prog);
  init_parser(p, tks, len);

  while (p->cur_tk.type != ENDOF) {
    if (p->cur_tk.type == POLICY) {
      Policy pol = parse_policy(p, tks);
      if (pol.name.value.ptr) {
        prog->stms[prog->count++] = pol;
        continue;
      }
    }
    next_token(p, tks);
  }
}

void free_node(Node *n) {
  if (!n)
    return;
  switch (n->tag) {
  case N_FORBID:
    free(n->forbid.ids);
    break;
  case N_REDACT:
    free(n->redact.ids);
    break;
  default:
    break;
  }
}

static void free_policy(Policy *pol) {
  free_node(&pol->forbid);
  free_node(&pol->redact);
  free_node(&pol->append);
}

void free_program(Program *prog) {
  if (!prog)
    return;
  for (int i = 0; i < prog->count; ++i) {
    free_policy(&prog->stms[i]);
  }
  free(prog->stms);
}

static int parse_params(Parser *p, Policy *pol, Token *tks) {
  if (p->peek_tk.type != IDENTIFIER) {
    return -1;
  }

  pol->params = malloc(2 * sizeof *pol->params);
  pol->nparams = 0;

  Identifier id = {.tk = p->peek_tk, .value = sv_from_token(&p->peek_tk)};
  pol->params[pol->nparams++] = id;
  next_token(p, tks);

  if (p->peek_tk.type == COMMA) {
    next_token(p, tks);

    if (p->peek_tk.type != IDENTIFIER) {
      return -1;
    }

    Identifier id2 = {.tk = p->peek_tk, .value = sv_from_token(&p->peek_tk)};
    pol->params[pol->nparams++] = id2;
    next_token(p, tks);
  }

  if (p->peek_tk.type != R_PAR) {
    return -1;
  }
  next_token(p, tks);

  return 0;
}

static Policy parse_policy(Parser *p, Token *tks) {
  Policy pol = (Policy){0};

  if (p->cur_tk.type != POLICY) {
    return pol;
  }

  if (p->peek_tk.type != IDENTIFIER) {
    return pol;
  }

  pol.name =
      (Identifier){.tk = p->peek_tk, .value = sv_from_token(&p->peek_tk)};
  next_token(p, tks);

  if (p->peek_tk.type != L_PAR) {
    return (Policy){0};
  }

  next_token(p, tks);

  if (parse_params(p, &pol, tks) != 0) {
    return (Policy){0};
  }

  while (p->cur_tk.type != END && p->cur_tk.type != ENDOF) {
    next_token(p, tks);

    if (p->cur_tk.type == END || p->cur_tk.type == ENDOF)
      break;

    Node n = parse_node(p, tks);
    switch (n.tag) {
    case N_FORBID:
      pol.forbid = n;
      break;
    default:
      break;
    }
  }

  if (p->cur_tk.type == END) {
    next_token(p, tks);
  }

  return pol;
}

static Node parse_node(Parser *p, Token *tks) {
  switch (p->peek_tk.type) {
  case FORBID:
    return parse_forbid(p, tks);
  default:
    return (Node){0};
  }
}

static Node parse_forbid(Parser *p, Token *tks) {
  Node n = {.tag = N_FORBID, .tk = p->peek_tk, .num_ids = 0};
  n.forbid.ids = NULL;
  next_token(p, tks);

  if (p->peek_tk.type != EQUALS) {
    return (Node){0};
  }

  next_token(p, tks);

  if (p->peek_tk.type != IDENTIFIER) {
    return (Node){0};
  }

  int cap = 4;
  n.forbid.ids = malloc((size_t)cap * sizeof *n.forbid.ids);

  if (n.forbid.ids == NULL) {
    return (Node){0};
  }

  next_token(p, tks);
  n.forbid.ids[n.num_ids++] =
      (Identifier){.tk = p->cur_tk, .value = sv_from_token(&p->cur_tk)};

  while (p->peek_tk.type == COMMA) {
    next_token(p, tks);
    if (p->peek_tk.type != IDENTIFIER) {
      return (Node){0};
    }

    if (n.num_ids == cap) {
      cap *= 2;
      Identifier *tmp = realloc(n.forbid.ids, (size_t)cap * sizeof *tmp);
      if (tmp == NULL) {
        return (Node){0};
      }
      n.forbid.ids = tmp;
    }

    next_token(p, tks);
    n.forbid.ids[n.num_ids++] =
        (Identifier){.tk = p->cur_tk, .value = sv_from_token(&p->cur_tk)};
  };

  return n;
}
