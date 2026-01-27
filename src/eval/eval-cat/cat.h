#ifndef CAT_H
#define CAT_H

#include "runtime.h"
int handler_email(int flag, int cat_id, PolicyRunTime *prt);
int handler_phone(int flag, int cat_id, PolicyRunTime *prt);
int handler_personal_id(int flag, int cat_id, PolicyRunTime *prt);

int handler_card(int flag, int cat_id, PolicyRunTime *prt);

int handler_ip(int flag, int cat_id, PolicyRunTime *prt);
int handler_sm_handle(int flag, int cat_id, PolicyRunTime *prt);
int handler_device_id(int flag, int cat_id, PolicyRunTime *prt);
int handler_online_id(int flag, int cat_id, PolicyRunTime *prt);

int handler_self_harm(int flag, int cat_id, PolicyRunTime *prt);
int handler_hate_speech(int flag, int cat_id, PolicyRunTime *prt);
int handler_violence(int flag, int cat_id, PolicyRunTime *prt);
#endif
