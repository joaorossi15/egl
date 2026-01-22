#ifndef DETECTOR_RESULT_H
#define DETECTOR_RESULT_H

#include <stdint.h>

typedef enum {
  DET_BACKEND_DETERMINISTIC = 0,
  DET_BACKEND_HYBRID = 1,
  DET_BACKEND_PROBABILISTIC = 2
} DetectorBackend;

typedef struct {
  int cat_id;
  DetectorBackend backend;
  float score;
  float threshold;
  int matched;
} DetectorResult;

typedef struct {
  int action_idx;
  DetectorResult dr;
} DetectorLog;

static inline float detector_default_threshold(int cat_id) {
  (void)cat_id;
  return 0.75f;
}

#endif
