#include "parser.h"
#include <stdint.h>

typedef enum { A_PASS, A_FORBID, A_REDACT, A_APPEND } Action;

typedef struct {
  uint64_t forbid_bitmask;
  uint64_t redact_bitmask;
  uint64_t append_bitmask;
  const char *mask_redact[128];   // mask for redact
  const char *append_string[128]; // value to append
  short exec_type;
} PolicyRunTime;

typedef struct {
  uint64_t categories_hit; // bitset from detectors
  Action action;           // final action under policy
  int redactions_applied;
  int disclaimer_appended;
} EnforcementResult;

void compile_policy(Program *p, PolicyRunTime *prt) {
  if (p->count < 1) {
    return;
  }

  for (int i = 0; i < p->count; i++) {
    if (p->stms[i].nparams == 1) {
      if (p->stms[i].params[0].tk.type == PRE) {
        prt->exec_type = 0;
      } else {
        prt->exec_type = 1;
      }

    } else if (p->stms[i].nparams == 2) {
      prt->exec_type = 2;
    }

    // extract forbid and write forbid bitmask

    // extract redact and write redact bitmask and masks

    // extract append and write append bitmask and values
  }
}

char *enforce(const char *value, const PolicyRunTime *p) {

  // evaluate forbid

  // evaluate redact

  // evaluate append

  return 0;
}
