#ifndef RUNTIME_OBJ_H
#define RUNTIME_OBJ_H

#include "parser.h"
#include "stdint.h"
#include <stddef.h>

#define MAX_CATS 32

// diversity subcategories mask
#define N_GENDER_REPRESENTATION (1ULL << 0)
#define N_RACIAL_REPRESENTATION (1ULL << 1)
#define N_ETHNIC_REPRESENTATION (1ULL << 2)
#define N_SOCIO_ECO_DIVERSITY (1ULL << 3)

// inclusion subcategories mask
#define N_GENDER_NEUTRAL_WORDING (1ULL << 4) // implemented on v0.1
#define EXCLUSIONARY_TERMS (1ULL << 5)       // implemented on v0.1

// equality subcategories mask
#define N_PARITY (1ULL << 6)
#define N_EQUAL_TREATMENT (1ULL << 7)
#define PREFERENCIAL_BIAS (1ULL << 8)

// accessibility subcategories mask
#define N_OUTPUT_CLARITY (1ULL << 9)
#define N_PLAIN_LANGUAGE (1ULL << 10)
#define N_MULTILINGUAL_SENSITIVITY (1ULL << 11)

// non-maleficence
// discrimination subcategories mask
#define HATE_SPEECH (1ULL << 16)
#define STEREOTYPING (1ULL << 17)
#define SLURS (1ULL << 18) // implemented on v0.1

// privacy subcategories mask
// all implemented on v0.1
#define PRIVACY (1ULL << 19)
#define PHONE (1ULL << 20)
#define EMAIL (1ULL << 21)
#define ADDRESS (1ULL << 22)
#define IP (1ULL << 23)

// bodily harm subcategories mask
#define SELF_HARM_ENCOURAGEMENT (1ULL << 24) // implemented on v0.1
#define DANGEROUS_INSTRUCTIONS (1ULL << 25)  // implemented on v0.1
#define VIOLENT_INST (1ULL << 26)

// medical risk subcategories mask
#define MEDICAL_RISK (1ULL << 27) // implemented on v0.1

typedef struct {
  uint32_t forbid_bitmask;
  uint32_t redact_bitmask;
  uint32_t append_bitmask;
  StrView mask_redact[MAX_CATS];   // mask for redact
  StrView append_string[MAX_CATS]; // value to append
  short exec_type;
  char *buf;
  size_t buf_cap;
} PolicyRunTime;

int compile_policy(Program *p, PolicyRunTime *prt);
#endif
