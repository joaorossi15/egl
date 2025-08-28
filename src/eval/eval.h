#ifndef EVAL_H
#define EVAL_H

#include "parser.h"
#include "stdint.h"

#define MAX_CATS 64

#define N_DIVERSITY (1ULL << 0)
#define N_INCLUSION (1ULL << 1)
#define N_EQUALITY (1ULL << 2)
#define N_ACCESSIBILITY (1ULL << 3)

// non-maleficence
#define DISCRIMINATION (1ULL << 16)
#define PRIVACY (1ULL << 17)
#define B_HARM (1ULL << 18)
#define MEDICAL_RISK (1ULL << 19)

typedef enum { A_PASS, A_FORBID, A_REDACT, A_APPEND } Action;

typedef struct {
  uint64_t forbid_bitmask;
  uint64_t redact_bitmask;
  uint64_t append_bitmask;
  StrView mask_redact[MAX_CATS];   // mask for redact
  StrView append_string[MAX_CATS]; // value to append
  short exec_type;
} PolicyRunTime;

typedef struct {
  uint64_t categories_hit; // bitset from detectors
  Action action;           // final action under policy
  int redactions_applied;
  int disclaimer_appended;
} EnforcementResult;

int compile_policy(Program *p, PolicyRunTime *prt);
#endif
