#ifndef SH_H
#define SH_H

static const char *const L_ENC[] = {"kill",     "hurt",      "harm", "end",
                                    "finish",   "cut",       "die",  "suicide",
                                    "selfharm", "self-harm", "off",  "unalive"};

static const char *const L_TARGET[] = {"yourself", "your", "yourself"};

static const char *const L_2P[] = {"you", "your", "u", "ur", "ya"};

static const char *const L_IMP[] = {"do",    "go",     "just",        "now",
                                    "must",  "should", "need",        "have",
                                    "gotta", "right",  "immediately", "now"};

static const char *const L_NEG[] = {"dont", "don't", "do",
                                    "not",  "never", "no"};

static const char *const L_SUPPORT[] = {
    "help",      "hotline",   "support",   "prevention", "lifeline", "crisis",
    "counselor", "therapist", "therapy",   "prevention", "resource", "988",
    "911",       "call",      "contact",   "talk",       "reach",    "reachout",
    "chat",      "text",      "block",     "report",     "flag",     "mute",
    "ignore",    "ban",       "moderator", "admin"};

static const char *const L_REPORT[] = {
    "news",     "report",   "study",    "studies",  "article",
    "articles", "policy",   "policies", "research", "paper",
    "papers",   "analysis", "analyses", "dataset",  "datasets"};

static const char *const L_ENC_AGGR[] = {
    "kys",          "k.y.s",          "k y s",        "kms",     "k.m.s",
    "unalive",      "disappear",      "endit",        "end-it",  "finishit",
    "finish-it",    "offyourself",    "off-yourself", "take",    "life",
    "takeyourlife", "take-your-life", "jump",         "cutdeep", "bleed",
    "bleeding"};

static const char *const L_2P_AGGR[] = {"urself", "yrself", "ya'll", "yall"};

static const char *const L_IMP_AGGR[] = {"pls", "please", "just", "simply"};

#endif
