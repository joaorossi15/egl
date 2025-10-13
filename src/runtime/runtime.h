#ifndef RUNTIME_OBJ_H
#define RUNTIME_OBJ_H

#include "parser.h"
#include "stdint.h"
#include <stddef.h>

#define MAX_CATS 32

// privacy subcategories mask
// all implemented on v0.1
#define PRIVACY (1ULL << 0)
#define PERSONAL_ID (1ULL << 1)
#define PHONE (1ULL << 2)
#define EMAIL (1ULL << 3)
#define ADDRESS (1ULL << 4)
#define FINANCIAL_ID (1ULL << 5)
#define CARD (1ULL << 6)
#define BANK_ACCOUNT (1ULL << 7)
#define TAX_ID (1ULL << 8)
#define ONLINE_ID (1ULL << 9)
#define IP (1ULL << 10)
#define HANDLE (1ULL << 11)
#define DEVICE_ID (1ULL << 12)
#define LOCATION (1ULL << 13)

// non-maleficence
#define NON_MALEFICENCE (1ULL << 15)
// discrimination subcategories mask
#define HATE_SPEECH (1ULL << 16) // initial version implemented on v0.1
#define STEREOTYPING (1ULL << 17)

// bodily harm subcategories mask
#define SELF_HARM_ENCOURAGEMENT (1ULL << 18) // implemented on v0.1
#define DANGEROUS_INSTRUCTIONS (1ULL << 19)  // implemented on v0.1
#define VIOLENT_INST (1ULL << 20)

// medical risk subcategories mask
#define MEDICAL_RISK (1ULL << 21) // implemented on v0.1

typedef struct {
  uint32_t forbid_bitmask;
  uint32_t redact_bitmask;
  uint32_t append_bitmask;
  StrView mask_redact[MAX_CATS];   // mask for redact
  StrView append_string[MAX_CATS]; // value to append
  short exec_type;

  char *buf;
  size_t buf_cap;
  int debug;
  int aggr;

  int counts[3][MAX_CATS];
  int total_by_action[3];
} PolicyRunTime;

int compile_policy(Program *p, PolicyRunTime *prt);
#endif
