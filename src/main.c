#include "lex/lexer.h"
#include <stdio.h>
#include <stdlib.h>

char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }

  int size = ftell(f);

  if (size < 0) {
    fclose(f);
    return NULL;
  }

  // return fp to start
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }

  char *buf = (char *)malloc(size);

  if (!buf) {
    fclose(f);
    return NULL;
  }

  size_t n = fread(buf, 1, size, f);
  if (n != size) {
    free(buf);
    fclose(f);
    return NULL;
  }

  fclose(f);
  buf[size] = '\0';
  return buf;
}

const char *token_type_to_string(TokenType type) {
  switch (type) {
  case POLICY:
    return "POLICY";
  case END:
    return "END";
  case REFUSAL:
    return "REFUSAL";
  case APPEND:
    return "APPEND";
  case REDACT:
    return "REDACT";
  case FORBID:
    return "FORBID";
  case TEXT:
    return "TEXT";
  case IDENTIFIER:
    return "IDENTIFIER";
  case COMMA:
    return "COMMA";
  case L_PAR:
    return "L_PAR";
  case R_PAR:
    return "R_PAR";
  case EQUALS:
    return "EQUALS";
  case ENDOF:
    return "EOF";
  default:
    return "UNKNOWN";
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: make <file.egl> \n");
    return -1;
  }

  char *buf = read_file(argv[1]);

  if (!buf) {
    printf("Could not read file: %s\n", argv[1]);
    return -1;
  }

  Lexer l;
  Token tk;
  init_lex(&l, buf);

  do {
    tk = new_token(&l);
    printf("TOKEN: %s ('%.*s') \n", token_type_to_string(tk.type), tk.len,
           tk.start ? tk.start : "");
  } while (tk.type != ENDOF);

  free(buf);
  return 0;
}
