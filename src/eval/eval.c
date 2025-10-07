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
    // {PRIVACY, handler_privacy},
    {PERSONAL_ID, handler_personal_id},
    {PHONE, handler_phone},
    {EMAIL, handler_email},
    // {ADDRESS, handler_address},
    // {FINANCIAL_ID, handler_financial_id},
    // {CARD, handler_card},
    // {BANK_ACCOUNT, handler_bank_account},
    // {TAX_ID, handler_tax_id},
    // {ONLINE_ID, handler_online_id},
    {IP, handler_ip},
    {HANDLE, handler_sm_handle},
    // {DEVICE_ID, handler_device_id},
    // {LOCATION, handler_location},
    // {NON_MALEFICENCE, handle_non_maleficence},
    // {HATE_SPEECH, handle_hate_speech},
    // {SELF_HARM_ENCOURAGEMENT, handler_em},
    // {DANGEROUS_INSTRUCTIONS, handler_di},
    // {MEDICAL_RISK, handler_mr},
};

int evaluate_rt_obj(PolicyRunTime *prt, char *input) {
  if (!input)
    return ERROR;

  memset(prt->counts, 0, sizeof prt->counts);
  memset(prt->total_by_action, 0, sizeof prt->total_by_action);

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

  short saw_forbid = 0;
  for (int i = 0; i < TABLE_SIZE; i++) {
    uint64_t m = table[i].mask_value;
    if (!(prt->forbid_bitmask & m))
      continue;
    int cat_id = id_from_cat_bit(m);
    int rc = table[i].handler_t(FORBID_FLAG, cat_id, prt);
    if (rc == FORBID_VIOLATION) {
      saw_forbid = 1;
      continue;
    }
    if (rc != OK)
      return rc;
  }

  if (saw_forbid && !prt->debug) {
    return FORBID_VIOLATION;
  }

  for (int i = 0; i < TABLE_SIZE; i++) {
    uint64_t m = table[i].mask_value;
    if (!((prt->redact_bitmask | prt->append_bitmask) & m))
      continue;
    int cat_id = id_from_cat_bit(m);

    if (prt->redact_bitmask & m) {
      int rc = table[i].handler_t(REDACT_FLAG, cat_id, prt);
      if (rc != OK)
        return rc;
    }
    if (prt->append_bitmask & m) {
      int rc = table[i].handler_t(APPEND_FLAG, cat_id, prt);
      if (rc != OK)
        return rc;
    }
  }

  if (saw_forbid)
    return FORBID_VIOLATION;

  return OK;
}
