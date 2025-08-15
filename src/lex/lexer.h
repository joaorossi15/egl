#ifndef LEXER_H
#define LEXER_H

typedef enum {
  ENDOF,
  POLICY,     // plc keyword
  END,        // end keyword
  FORBID,     // forbid keyword
  REFUSAL,    // refusal keyword
  REDACT,     // redact keyword
  TEXT,       // text keyword
  APPEND,     // append keyword
  COMMA,      // ','
  L_PAR,      // '('
  R_PAR,      // ')'
  IDENTIFIER, // identifier for params and func names
  EQUALS,     // ':'
  ILLEGAL     //
} TokenType;

typedef struct {
  TokenType type;
  const char *start;
  int len;
} Token;

typedef struct {
  const char *input;
  int pos;
  int next_pos;
  char c;
  int len;
} Lexer;

typedef struct {
  const char *name;
  TokenType type;
} Keyword;

void init_lex(Lexer *l, const char *input);
Token new_token(Lexer *l);

#endif
