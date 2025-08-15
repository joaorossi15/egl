#include "parser.h"
#include <stdio.h>
#include <stdlib.h>

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

void next_token(Parser *p, Token *tks) {
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

void free_program(Program *prog) { free(prog->stms); }

int parse_params(Parser *p, Policy *pol, Token *tks) {
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

Policy parse_policy(Parser *p, Token *tks) {
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
  }

  if (p->cur_tk.type == END) {
    next_token(p, tks);
  }

  return pol;
}
