#ifndef PARSER_H
#define PARSER_H
#include "lexer.h"
// AST node for each type
// AST base
//
//

typedef enum { N_I, N_POLICY, N_FORBID, N_REDACT, N_TEXT, N_APPEND } Tag;

typedef struct {
  const char *ptr;
  int len;
} StrView;

typedef struct {
  Token tk;
  StrView value;
} Identifier;

typedef struct Node {
  Tag tag;
  Token tk;
  int num_ids;

  union {

    struct {
      Identifier *ids;
    } forbid;

    struct {
      Identifier *ids;
    } redact;

    struct {
      Identifier *ids;
      char **text;
    } append;
  };
} Node;

typedef struct {
  Identifier *params;
  int nparams;
  Identifier name;
  Node forbid;
  Node redact;
  Node append;
} Policy;

typedef struct {
  int cur_pos;
  Token cur_tk;
  Token peek_tk;
  int tks_len;
} Parser;

typedef struct {
  Policy *stms;
  int count;
  int cap;
} Program;

void init_parser(Parser *p, Token *tks, int len);
void init_program(Program *p);
void parse_program(Program *prog, Parser *p, Token *tks, int len);
void free_program(Program *prog);
#endif
