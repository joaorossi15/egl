#ifndef EVAL_H
#define EVAL_H

#include "runtime.h"
#include <stdint.h>

typedef struct {
  uint32_t sc_hit_bitmask;
  uint8_t forbid_total;
  uint8_t redact_total;
  uint8_t append_total;
} Evaluated;

int evaluate_rt_obj(PolicyRunTime *plt);

#endif
