#include "eval.h"
#include "detector_result.h"
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
    {ONLINE_ID, handler_online_id},
    {IP, handler_ip},
    {HANDLE, handler_sm_handle},
    {DEVICE_ID, handler_device_id},
    // {LOCATION, handler_location},
    // {NON_MALEFICENCE, handle_non_maleficence},
    {DISCRIMINATION, handler_hate_speech},
    {SELF_HARM_ENCOURAGEMENT, handler_self_harm},
    {DANGEROUS_INSTRUCTIONS, handler_di},
    // {MEDICAL_RISK, handler_mr},
};

static inline DetectorResult
eval_legacy_detector(int action_idx, int cat_id, PolicyRunTime *prt,
                     int (*handler)(int, int, PolicyRunTime *), int flag,
                     int *out_rc) {
  DetectorResult dr;
  dr.cat_id = cat_id;

  dr.backend = DET_BACKEND_DETERMINISTIC;
  dr.threshold = detector_default_threshold(cat_id);
  dr.score = 0.0f;
  dr.matched = 0;

  prt->last_cat_id = cat_id;
  prt->last_backend = DET_BACKEND_DETERMINISTIC;
  prt->last_score = 0.0f;
  prt->last_threshold = dr.threshold;

  long before = prt->counts[action_idx][cat_id];

  int rc = handler(flag, cat_id, prt);
  if (out_rc)
    *out_rc = rc;

  long after = prt->counts[action_idx][cat_id];
  int hit = (after > before);

  if (prt->last_cat_id == cat_id) {
    dr.backend = prt->last_backend;

    float thr = prt->last_threshold;
    if (!(thr > 0.0f) || thr > 1.0f) {
      thr = detector_default_threshold(cat_id);
    }

    dr.score = prt->last_score;
    dr.threshold = thr;
  } else {
    dr.score = hit ? 1.0f : 0.0f;
    dr.threshold = detector_default_threshold(cat_id);
    dr.backend = DET_BACKEND_DETERMINISTIC;
  }

  dr.matched = (dr.score >= dr.threshold) ? 1 : 0;

  return dr;
}

static int push_detector_log(DetectorLog **arr, size_t *len, size_t *cap,
                             int action_idx, DetectorResult dr) {
  if (*len >= *cap) {
    size_t new_cap = (*cap == 0) ? 16 : (*cap * 2);
    void *p = realloc(*arr, new_cap * sizeof(**arr));

    if (!p)
      return ERROR;

    *arr = (DetectorLog *)p;
    *cap = new_cap;
  }

  (*arr)[*len].action_idx = action_idx;
  (*arr)[*len].dr = dr;
  (*len)++;

  return OK;
}

static inline void reset_last_detector(PolicyRunTime *prt, int cat_id) {
  prt->last_cat_id = cat_id;
  prt->last_backend = DET_BACKEND_DETERMINISTIC;
  prt->last_score = 0.0f;
  prt->last_threshold = -1.0f;
}

int evaluate_rt_obj(PolicyRunTime *prt, char *input) {
  if (!input)
    return ERROR;

  prt->det_len = 0;

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
    reset_last_detector(prt, cat_id);

    int rc = OK;
    DetectorResult dr = eval_legacy_detector(
        COUNTS_FORBID, cat_id, prt, table[i].handler_t, FORBID_FLAG, &rc);

    if (push_detector_log(&prt->det_logs, &prt->det_len, &prt->det_cap,
                          COUNTS_FORBID, dr) != OK) {
      return ERROR;
    }

    if (prt->debug) {
      const char *model =
          prt->det_model[dr.cat_id][0] ? prt->det_model[dr.cat_id] : "default";
      fprintf(stderr,
              "[detector] model=%s cat_id=%d score=%.6f thr=%.6f matched=%d\n",
              model, dr.cat_id, dr.score, dr.threshold, dr.matched);
    }

    if (rc != OK && rc != FORBID_VIOLATION)
      return rc;

    if (dr.matched) {
      saw_forbid = 1;
      continue;
    }
  }

  if (saw_forbid && !prt->debug) {
    return FORBID_VIOLATION;
  }

  for (int i = 0; i < TABLE_SIZE; i++) {
    uint64_t m = table[i].mask_value;
    if (!((prt->redact_bitmask | prt->append_bitmask) & m))
      continue;

    if (prt->redact_bitmask & m) {
      int cat_id = id_from_cat_bit(m);
      reset_last_detector(prt, cat_id);
      int rc = OK;
      DetectorResult dr = eval_legacy_detector(
          COUNTS_REDACT, cat_id, prt, table[i].handler_t, REDACT_FLAG, &rc);

      if (push_detector_log(&prt->det_logs, &prt->det_len, &prt->det_cap,
                            COUNTS_REDACT, dr) != OK) {
        return ERROR;
      }

      if (prt->debug) {
        const char *model = prt->det_model[dr.cat_id][0]
                                ? prt->det_model[dr.cat_id]
                                : "default";
        fprintf(
            stderr,
            "[detector] model=%s cat_id=%d score=%.6f thr=%.6f matched=%d\n",
            model, dr.cat_id, dr.score, dr.threshold, dr.matched);
      }

      if (rc != OK)
        return rc;
    }

    if (prt->append_bitmask & m) {
      int cat_id = id_from_cat_bit(m);
      reset_last_detector(prt, cat_id);
      int rc = OK;
      DetectorResult dr = eval_legacy_detector(
          COUNTS_APPEND, cat_id, prt, table[i].handler_t, APPEND_FLAG, &rc);

      if (push_detector_log(&prt->det_logs, &prt->det_len, &prt->det_cap,
                            COUNTS_APPEND, dr) != OK) {
        return ERROR;
      }

      if (prt->debug) {
        const char *model = prt->det_model[dr.cat_id][0]
                                ? prt->det_model[dr.cat_id]
                                : "default";
        fprintf(
            stderr,
            "[detector] model=%s cat_id=%d score=%.6f thr=%.6f matched=%d\n",
            model, dr.cat_id, dr.score, dr.threshold, dr.matched);
      }

      if (rc != OK)
        return rc;
    }
  }

  if (saw_forbid)
    return FORBID_VIOLATION;

  return OK;
}
