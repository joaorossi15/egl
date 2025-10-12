#ifndef HELPER_CAT_H
#define HELPER_CAT_H

#include "runtime.h"
int action_from_flag(int flag);
int ensure_cap(PolicyRunTime *prt, size_t need);
int process_match_and_act(int flag, int cat_id, PolicyRunTime *prt, char *beg,
                          char *end, short *saw_forbid);
int is_handle_char(unsigned char c);
char *scan_handle_end(char *p);
#endif
