#ifndef EVAL_H
#define EVAL_H

#include "runtime.h"
#include <stdint.h>

#define TABLE_SIZE 32
#define FORBID_FLAG 0
#define REDACT_FLAG 1
#define APPEND_FLAG 2

#define OK 0
#define ERROR -1
#define FORBID_VIOLATION -2

typedef struct {
  uint32_t sc_hit_bitmask;
  uint8_t forbid_total;
  uint8_t redact_total;
  uint8_t append_total;
} Evaluated;

typedef struct {
  uint32_t mask_value;
  int (*handler_t)(int, int, PolicyRunTime *);
} TableEntry;

int evaluate_rt_obj(PolicyRunTime *prt, char *input);

#endif
