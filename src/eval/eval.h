#ifndef EVAL_H
#define EVAL_H

#include "runtime.h"
#include <stdint.h>

#define TABLE_SIZE 32

typedef struct {
  uint32_t sc_hit_bitmask;
  uint8_t forbid_total;
  uint8_t redact_total;
  uint8_t append_total;
} Evaluated;

typedef struct {
  uint32_t mask_value;
  int (*handler_t)(int, char[static 1]);
} TableEntry;

int evaluate_rt_obj(PolicyRunTime *prt, char *input);

#endif
