#ifndef CAT_H
#define CAT_H

#include "runtime.h"
int handler_email(int flag, int cat_id, PolicyRunTime *prt);
int handler_phone(int flag, int cat_id, PolicyRunTime *prt);
int handler_personal_id(int flag, int cat_id, PolicyRunTime *prt);

int handler_ip(int flag, int cat_id, PolicyRunTime *prt);
int handler_sm_handle(int flag, int cat_id, PolicyRunTime *prt);
#endif
