#include "eval.h"
#include "runtime.h"
#include <stdio.h>

int handler_ngw(int flag, char input[static 1]);
int handler_et(int flag, char input[static 1]);
int handler_hs(int flag, char input[static 1]);
int handler_pv(int flag, char input[static 1]);
int handler_sh(int flag, char input[static 1]);
int handler_di(int flag, char input[static 1]);
int handler_mr(int flag, char input[static 1]);
int find_forbid(uint32_t bitmaks, char input[static 1]);

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
  // call forbid function with bitmask
  if (prt->forbid_bitmask != 0) {
    int f = find_forbid(prt->forbid_bitmask, input);
  }

  // call redact function with bitmask

  // call append function with bitmask

  // populate the evaluated struct

  return 0;
}

int handler_ngw(int flag, char input[static 1]) {
  printf("flag %d: found non_gender_neutral_wording\n", flag);
  return 0;
}

int handler_et(int flag, char input[static 1]) {
  printf("flag %d: found exclusionary_terms\n", flag);
  return 0;
}

int handler_hs(int flag, char input[static 1]) {
  printf("flag %d: found hate_speech\n", flag);
  return 0;
}

int handler_pv(int flag, char input[static 1]) {
  printf("flag %d: found privacy\n", flag);
  return 0;
}

int handler_sh(int flag, char input[static 1]) {
  printf("flag %d: found self_harm_encouragement\n", flag);
  return 0;
}

int handler_di(int flag, char input[static 1]) {
  printf("flag %d: found dangerous_instructions\n", flag);
  return 0;
}

int handler_mr(int flag, char input[static 1]) {
  printf("flag %d: found medical_risk\n", flag);
  return 0;
}

int find_forbid(uint32_t bitmask, char input[static 1]) {
  for (int i = 0; i < TABLE_SIZE; i++) {
    if (bitmask & table[i].mask_value) {
      table[i].handler_t(0, input);
    }
  }
  return 0;
}
