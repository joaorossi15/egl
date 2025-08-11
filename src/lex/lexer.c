#include "lexer.h"
#include <string.h>

Keyword kws[] = {{"policy", POLICY}, {"end", END},       {"refusal", REFUSAL},
                 {"append", APPEND}, {"redact", REDACT}, {"forbid", FORBID},
                 {"text", TEXT},     {NULL, 0}};

TokenType lookup_kws(const char *start, size_t len) {
  for (int i = 0; kws[i].name != NULL; i++) {
    if (strlen(kws[i].name) == len && strncmp(start, kws[i].name, len) == 0) {
      return kws[i].type;
    }
  }

  return IDENTIFIER;
}

void lexer_read(Lexer *l) {
  if (l->next_pos >= l->len) {
    l->c = 0;
  } else {
    l->c = l->input[l->next_pos];
  }

  l->pos = l->next_pos;
  l->next_pos++;
}

void lexer_skip(Lexer *l) {
  while (l->c == '\t' || l->c == '\r' || l->c == ' ' || l->c == '\n') {
    lexer_read(l);
  }
}

void init_lex(Lexer *l, const char *input) {
  l->input = input;
  l->pos = 0;
  l->next_pos = 0;
  l->c = 0;
  l->len = strlen(l->input);
  lexer_read(l);
}

Token construct_lex(Lexer *l) {
  const char *start = &l->input[l->pos];
  int len = 0;

  while ((l->c >= 'a' && l->c <= 'z') || (l->c >= 'A' && l->c <= 'Z') ||
         l->c == '_') {
    lexer_read(l);
    len++;
  }

  TokenType tt = lookup_kws(start, len);

  return (Token){.start = start, .len = len, .type = tt};
}

Token new_token(Lexer *l) {
  Token tk = {0};
  lexer_skip(l);

  switch (l->c) {
  case ',':
    tk.start = &l->input[l->pos];
    tk.len = 1;
    tk.type = COMMA;
    lexer_read(l);
    break;
  case '(':
    tk.start = &l->input[l->pos];
    tk.len = 1;
    tk.type = L_PAR;
    lexer_read(l);
    break;
  case ')':
    tk.start = &l->input[l->pos];
    tk.len = 1;
    tk.type = R_PAR;
    lexer_read(l);
    break;
  case ':':
    tk.start = &l->input[l->pos];
    tk.len = 1;
    tk.type = EQUALS;
    lexer_read(l);
    break;
  case 0:
    tk.start = NULL;
    tk.len = 0;
    tk.type = ENDOF;
    break;
  default:
    if ((l->c >= 'a' && l->c <= 'z') || (l->c >= 'A' && l->c <= 'Z')) {
      tk = construct_lex(l);
    } else {
      tk.start = &l->input[l->pos];
      tk.len = 1;
      tk.type = ILLEGAL;
      lexer_read(l);
    }
    break;
  }

  return tk;
}
