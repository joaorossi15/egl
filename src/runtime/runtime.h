#ifndef RUNTIME_OBJ_H
#define RUNTIME_OBJ_H

#include "detector_result.h"
#include "parser.h"
#include "stdint.h"
#include <stddef.h>

#define MAX_CATS 16

// privacy subcategories mask
// OK
#define PHONE (1ULL << 0)
#define EMAIL (1ULL << 1)

//
#define CARD (1ULL << 2)
#define BANK_ACCOUNT (1ULL << 3)
#define TAX_ID (1ULL << 4)

// OK
#define IP (1ULL << 5)
#define HANDLE (1ULL << 6)
#define DEVICE_ID (1ULL << 7)

// idk
#define ADDRESS (1ULL << 8)
#define COORDINATES (1ULL << 9)

// non-maleficence
// discrimination subcates: hate speech, stereotyping mask
#define DISCRIMINATION (1ULL << 10)          // ok
#define SELF_HARM_ENCOURAGEMENT (1ULL << 11) // ok
#define VIOLENCE (1ULL << 12)
// medical risk subcategories mask
#define MEDICAL_RISK (1ULL << 13)

typedef struct {
  uint32_t forbid_bitmask;
  uint32_t redact_bitmask;
  uint32_t append_bitmask;
  StrView mask_redact[MAX_CATS];
  StrView append_string[MAX_CATS];
  short exec_type;

  char *buf;
  size_t buf_cap;
  int debug;
  int aggr;

  int counts[3][MAX_CATS];
  int total_by_action[3];

  DetectorLog *det_logs;
  size_t det_len;
  size_t det_cap;

  DetectorBackend last_backend;
  float last_score;
  float last_threshold;
  int last_cat_id;

  float det_threshold[MAX_CATS];
  char det_model[MAX_CATS][512];

} PolicyRunTime;

int compile_policy(Program *p, PolicyRunTime *prt);
int cat_id_from_cstr(const char *s);
#endif
