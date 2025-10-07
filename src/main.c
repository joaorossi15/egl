#include "eval/eval.h"
#include "helpers/print.h"
#include "lex/lexer.h"
#include "parser/parser.h"
#include "pragma/pragma.h"
#include "runtime/runtime.h"
#include <stdint.h>
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
  if ((int)n != size) {
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
    return "ENDOF";
  case STR:
    return "STR";
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

  short is_debug_on = scan_debug_pragma(buf);

  Lexer l;
  Token tk;
  init_lex(&l, buf);
  Token tks[100];
  int i = 0;
  do {
    tk = new_token(&l);
    tks[i] = tk;
    i++;
  } while (tk.type != ENDOF);

  Parser p = {0};
  Program prog = {0};
  parse_program(&prog, &p, tks, i);
  if (p.e_count != 0) {
    for (int i = 0; i < p.e_count; i++) {
      if (p.errors[i]) {
        fprintf(stderr, "%s\n", p.errors[i]);
      }
    }
  }

  PolicyRunTime prt = {0};

  if (compile_policy(&prog, &prt) != 0) {
    return -1;
  }

  prt.debug = is_debug_on;
  int rc = evaluate_rt_obj(
      &prt, "phone=+55(11)12345678 email@email.com @test 192.168.0.1");

  if (rc == FORBID_VIOLATION) {
    printf("FORBIDDEN OUTPUT\n");
    print_debug_summary(&prt);
  } else if (rc == OK) {
    printf("%s\n", prt.buf);
    print_debug_summary(&prt);
  } else {
    fprintf(stderr, "EVAL ERROR\n");
  }

  free(prt.buf);
  free_program(&prog);
  free(buf);

  return 0;
}
