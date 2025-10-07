#include "parser.h"
#include "runtime.h"
void dump_program(const Program *prog);
char *long_to_binary(unsigned long k);
void print_debug_summary(const PolicyRunTime *prt);
void print_eval_json(PolicyRunTime *prt, const char *mode, int return_code);
