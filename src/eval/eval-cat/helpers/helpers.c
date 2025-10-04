#include "../eval.h"
#include "helper.h"

int action_from_flag(int flag) {
  return (flag == FORBID_FLAG)   ? 0
         : (flag == REDACT_FLAG) ? 1
         : (flag == APPEND_FLAG) ? 2
                                 : -1;
}
