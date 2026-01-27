#include "eval/eval.h"
#include "helpers/output.h"
#include "lex/lexer.h"
#include "parser/parser.h"
#include "pragma/pragma.h"
#include "runtime/runtime.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int apply_detector_pragma_cb(const char *category, const char *model,
                                    float threshold, void *ctx) {
  PolicyRunTime *prt = (PolicyRunTime *)ctx;
  if (!prt || !category || !category[0])
    return 1;

  int cat_id = cat_id_from_cstr(category);
  if (cat_id < 0 || cat_id >= MAX_CATS) {
    fprintf(stderr, "[pragma] @detector: unknown category '%s'\n", category);
    return 1;
  }

  if (model && model[0]) {
    strncpy(prt->det_model[cat_id], model, sizeof(prt->det_model[cat_id]) - 1);
    prt->det_model[cat_id][sizeof(prt->det_model[cat_id]) - 1] = '\0';
  }

  if (threshold >= 0.0f) {
    prt->det_threshold[cat_id] = threshold;
  }

  return 0;
}

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

  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }

  char *buf = (char *)malloc((size_t)size + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  size_t n = fread(buf, 1, (size_t)size, f);
  if ((int)n != size) {
    free(buf);
    fclose(f);
    return NULL;
  }

  fclose(f);
  buf[size] = '\0';
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 3 && argc != 4) {
    printf("Usage: ./egl <file.egl> [flags] [input]\n");
    return -1;
  }

  char *buf = read_file(argv[1]);
  if (!buf) {
    printf("Could not read file: %s\n", argv[1]);
    return -1;
  }

  int json_mode = 0;
  int i = 2;
  char *input_str = NULL;

  for (; i < argc; i++) {
    if (argv[i][0] != '-')
      break;

    if (strcmp(argv[i], "--json") == 0) {
      json_mode = 1;
    } else {
      fprintf(stderr, "Unknown flag: %s\n", argv[i]);
      free(buf);
      return -1;
    }
  }

  if (i < argc) {
    input_str = argv[i];
  } else {
    fprintf(stderr, "Error: no input string provided\n");
    free(buf);
    return 3;
  }

  short is_debug_on = scan_debug_pragma(buf);
  short is_aggressive_on = scan_aggressive_pragma(buf);

  Lexer l;
  Token tk;
  init_lex(&l, buf);

  Token tks[100];
  int ntoks = 0;
  do {
    tk = new_token(&l);
    tks[ntoks++] = tk;
  } while (tk.type != ENDOF);

  Parser p = (Parser){0};
  Program prog = (Program){0};
  parse_program(&prog, &p, tks, ntoks);

  if (p.e_count != 0) {
    for (int j = 0; j < p.e_count; j++) {
      if (p.errors[j])
        fprintf(stderr, "%s\n", p.errors[j]);
    }
  }

  PolicyRunTime prt = (PolicyRunTime){0};

  if (compile_policy(&prog, &prt) != 0) {
    free_program(&prog);
    free(buf);
    return -1;
  }

  for (int c = 0; c < MAX_CATS; c++) {
    prt.det_model[c][0] = '\0';
    prt.det_threshold[c] = -1.0f;
  }

  scan_detector_pragmas(buf, apply_detector_pragma_cb, &prt);

  prt.debug = is_debug_on;
  prt.aggr = is_aggressive_on;

  int rc = evaluate_rt_obj(&prt, input_str);

  if (rc == ERROR || prt.debug == -1) {
    fprintf(stderr, "EVAL ERROR\n");
  } else {
    if (json_mode) {
      const char *exec_type = (prt.exec_type == 2)   ? "pre_post"
                              : (prt.exec_type == 0) ? "pre"
                                                     : "post";

      print_eval_json(&prt, prt.det_logs, prt.det_len, exec_type, rc);
    } else {
      if (rc == FORBID_VIOLATION) {
        printf("FORBIDDEN OUTPUT\n");
        print_debug_summary(&prt);
      } else {
        printf("%s\n", prt.buf);
        if (prt.debug) {
          print_debug_summary(&prt);
        }
      }
    }
  }

  free(prt.det_logs);
  free(prt.buf);
  free_program(&prog);
  free(buf);

  return 0;
}

// int main(int argc, char **argv) {
//   if (argc < 2) {
//     printf("Usage: ./egl <file.egl> [flags]\n");
//     return -1;
//   }
//
//   char *buf = read_file(argv[1]);
//   if (!buf) {
//     printf("Could not read file: %s\n", argv[1]);
//     return -1;
//   }
//
//   int json_mode = 0;
//
//   /* parse flags only */
//   for (int i = 2; i < argc; i++) {
//     if (strcmp(argv[i], "--json") == 0) {
//       json_mode = 1;
//     } else {
//       fprintf(stderr, "Unknown flag: %s\n", argv[i]);
//       free(buf);
//       return -1;
//     }
//   }
//
//   short is_debug_on = scan_debug_pragma(buf);
//   short is_aggressive_on = scan_aggressive_pragma(buf);
//
//   /* ===== parse policy once ===== */
//
//   Lexer l;
//   Token tk;
//   init_lex(&l, buf);
//
//   Token tks[100];
//   int ntoks = 0;
//   do {
//     tk = new_token(&l);
//     tks[ntoks++] = tk;
//   } while (tk.type != ENDOF);
//
//   Parser p = (Parser){0};
//   Program prog = (Program){0};
//   parse_program(&prog, &p, tks, ntoks);
//
//   if (p.e_count != 0) {
//     for (int j = 0; j < p.e_count; j++) {
//       if (p.errors[j])
//         fprintf(stderr, "%s\n", p.errors[j]);
//     }
//   }
//
//   PolicyRunTime prt = (PolicyRunTime){0};
//
//   if (compile_policy(&prog, &prt) != 0) {
//     free_program(&prog);
//     free(buf);
//     return -1;
//   }
//
//   prt.debug = is_debug_on;
//   prt.aggr = is_aggressive_on;
//
//   /* ===== interactive loop ===== */
//
//   char input_buf[4096];
//
//   printf("EGL interactive mode. Type text and press ENTER (Ctrl+C to quit)\n
//   ");
//
//   while (1) {
//     printf("> ");
//     fflush(stdout);
//
//     if (!fgets(input_buf, sizeof(input_buf), stdin))
//       break;
//
//     /* remove newline */
//     input_buf[strcspn(input_buf, "\n")] = '\0';
//
//     if (input_buf[0] == '\0')
//       continue;
//
//     int rc = evaluate_rt_obj(&prt, input_buf);
//
//     if (rc == ERROR || prt.debug == -1) {
//       fprintf(stderr, "EVAL ERROR\n");
//       continue;
//     }
//
//     if (json_mode) {
//       const char *exec_type = (prt.exec_type == 2)   ? "pre_post"
//                               : (prt.exec_type == 0) ? "pre"
//                                                      : "post";
//
//       print_eval_json(&prt, prt.det_logs, prt.det_len, exec_type, rc);
//     } else {
//       if (rc == FORBID_VIOLATION) {
//         printf("FORBIDDEN OUTPUT\n");
//       } else {
//         printf("%s\n", prt.buf);
//       }
//
//       print_debug_summary(&prt);
//     }
//
//     /* clear detector logs for next iteration */
//     prt.det_len = 0;
//   }
//
//   free(prt.det_logs);
//   free(prt.buf);
//   free_program(&prog);
//   free(buf);
//
//   return 0;
// }
