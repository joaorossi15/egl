#include "eval.h"
#include "eval-cat/cat.h"
#include "runtime.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int id_from_cat_bit(int bit) {
  int id = 0;
  while (bit > 1) {
    bit >>= 1;
    id++;
  }
  return id;
}

TableEntry table[32] = {
    // {N_GENDER_NEUTRAL_WORDING, handler_ngw},
    // {EXCLUSIONARY_TERMS, handler_et},
    // {SLURS, handler_hs},
    // {PHONE, handler_ph},
    {EMAIL, handler_em},
    // {ADDRESS, handler_addr},
    // {IP, handler_ip},
    // {PRIVACY, handler_pv},
    // {SELF_HARM_ENCOURAGEMENT, handler_sh},
    // {DANGEROUS_INSTRUCTIONS, handler_di},
    // {MEDICAL_RISK, handler_mr},
};

int evaluate_rt_obj(PolicyRunTime *prt, char *input) {
  if (!input)
    return ERROR;
  size_t len = strlen(input);
  size_t need = len + 1;

  if (prt->buf == NULL || prt->buf_cap < need) {
    size_t cap = prt->buf_cap ? prt->buf_cap : 64;
    while (cap < need)
      cap *= 2;
    char *new_block = realloc(prt->buf, cap);
    if (!new_block)
      return ERROR;
    prt->buf = new_block;
    prt->buf_cap = cap;
  }

  memcpy(prt->buf, input, need);

  for (int i = 0; i < TABLE_SIZE; i++) {
    const uint32_t m = table[i].mask_value;
    int flag = -1;

    if (prt->forbid_bitmask & m)
      flag = FORBID_FLAG;
    else if (prt->redact_bitmask & m)
      flag = REDACT_FLAG;
    else if (prt->append_bitmask & m)
      flag = APPEND_FLAG;
    else
      continue;

    int cat_id = id_from_cat_bit(m);
    const int rc = table[i].handler_t(flag, cat_id, prt);
    if (rc != OK)
      return rc;
    if (flag == FORBID_FLAG)
      return FORBID_VIOLATION;
  }
  return OK;
}
