#include "eval.h"
#include "runtime.h"
#include <stdio.h>

int handler_ngw(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_et(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_hs(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_pv(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_sh(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_di(int flag, PolicyRunTime *prt, char input[static 1]);
int handler_mr(int flag, PolicyRunTime *prt, char input[static 1]);

TableEntry table[32] = {
    {N_GENDER_NEUTRAL_WORDING, handler_ngw},
    {EXCLUSIONARY_TERMS, handler_et},
    {SLURS, handler_hs},
    {PRIVACY, handler_pv},
    {SELF_HARM_ENCOURAGEMENT, handler_sh},
    {DANGEROUS_INSTRUCTIONS, handler_di},
    {MEDICAL_RISK, handler_mr},
};

int evaluate_rt_obj(PolicyRunTime *prt, char input[static 1]) {
  if (prt->forbid_bitmask != 0) {
    for (int i = 0; i < TABLE_SIZE; i++) {
      if (prt->forbid_bitmask & table[i].mask_value) {
        table[i].handler_t(FORBID_FLAG, prt, input);
      }
    }
  }

  if (prt->redact_bitmask != 0) {
    for (int i = 0; i < TABLE_SIZE; i++) {
      if (prt->redact_bitmask & table[i].mask_value) {
        table[i].handler_t(REDACT_FLAG, prt, input);
      }
    }
  }

  if (prt->append_bitmask != 0) {
    for (int i = 0; i < TABLE_SIZE; i++) {
      if (prt->append_bitmask & table[i].mask_value) {
        table[i].handler_t(APPEND_FLAG, prt, input);
      }
    }
  }

  return 0;
}

int handler_ngw(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found non_gender_neutral_wording\n", flag);
  return 0;
}

int handler_et(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found exclusionary_terms\n", flag);
  return 0;
}

int handler_hs(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found hate_speech\n", flag);
  return 0;
}

int handler_pv(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found privacy\n", flag);
  return 0;
}

int handler_sh(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found self_harm_encouragement\n", flag);
  return 0;
}

int handler_di(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found dangerous_instructions\n", flag);
  return 0;
}

int handler_mr(int flag, PolicyRunTime *prt, char input[static 1]) {
  printf("flag %d: found medical_risk\n", flag);
  return 0;
}
