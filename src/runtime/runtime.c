#include "runtime.h"
#include "parser.h"
#include <stdio.h>
#include <string.h>

static inline uint32_t cat_bit_from_id(int id) {
  return (id >= 0) ? (1ULL << id) : 0;
}

static inline int sv_eq_cstr(StrView sv, const char *lit) {
  size_t n = strlen(lit);

  return (sv.len == (int)n) && (sv.ptr && memcmp(sv.ptr, lit, n) == 0);
}

static inline int cat_id_from_sv(StrView id) {
  if (sv_eq_cstr(id, "privacy"))
    return 0;
  if (sv_eq_cstr(id, "personal_id"))
    return 1;
  if (sv_eq_cstr(id, "phone"))
    return 2;
  if (sv_eq_cstr(id, "email"))
    return 3;
  // if (sv_eq_cstr(id, "financial_id"))
  //   return 5;
  if (sv_eq_cstr(id, "credit_card"))
    return 6;
  // if (sv_eq_cstr(id, "bank_account"))
  //   return 7;
  // if (sv_eq_cstr(id, "tax_id"))
  //   return 8;
  if (sv_eq_cstr(id, "online_id"))
    return 9;
  if (sv_eq_cstr(id, "ip"))
    return 10;
  if (sv_eq_cstr(id, "username"))
    return 11;
  if (sv_eq_cstr(id, "device_id"))
    return 12;
  // if (sv_eq_cstr(id, "location"))
  //   return 13;
  // if (sv_eq_cstr(id, "address"))
  //   return 14;
  // if (sv_eq_cstr(id, "coordinations"))
  //   return 4;
  // if (sv_eq_cstr(id, "non_maleficence"))
  //  return 22;
  if (sv_eq_cstr(id, "discrimination"))
    return 16;
  if (sv_eq_cstr(id, "self_harm"))
    return 18;
  if (sv_eq_cstr(id, "violence"))
    return 19;
  // if (sv_eq_cstr(id, "medical_risk"))
  //   return 21;
  return -1;
}

int cat_id_from_cstr(const char *s) {
  if (!s)
    return -1;

  StrView sv;
  sv.ptr = s;
  sv.len = strlen(s);
  return cat_id_from_sv(sv);
}

int extract_forbid(const Node *n, PolicyRunTime *prt) {
  if (n->num_ids == 0) {
    return 0;
  }

  for (int i = 0; i < n->num_ids; i++) {
    int id = cat_id_from_sv(n->forbid.ids[i].value);
    if ((id < 0) || (id >= MAX_CATS)) {
      fprintf(stderr, "unknown forbid category: %.*s\n",
              n->forbid.ids[i].value.len, n->forbid.ids[i].value.ptr);
      return -1;
    }
    prt->forbid_bitmask |= cat_bit_from_id(id);
  }

  return 0;
}

int extract_redact(Node *n, PolicyRunTime *prt) {
  if (n->num_ids == 0) {
    return 0;
  }

  for (int i = 0; i < n->num_ids; i++) {
    StrView mask = n->pair[i].value;
    int id = cat_id_from_sv(n->pair[i].i.value);
    if (id < 0 || id >= MAX_CATS) {
      fprintf(stderr, "unknown redact category: %.*s\n", n->pair[i].i.value.len,
              n->pair[i].i.value.ptr);
      return -1;
    }
    if (mask.len != 1) {
      fprintf(stderr, "redact lenght cannot be less or greater than one\n");
      return -1;
    }
    prt->redact_bitmask |= cat_bit_from_id(id);
    prt->mask_redact[id] = mask;
  }

  return 0;
}

int extract_append(Node *n, PolicyRunTime *prt) {
  if (n->num_ids == 0) {
    return 0;
  }

  for (int i = 0; i < n->num_ids; i++) {
    StrView mask = n->pair[i].value;
    int id = cat_id_from_sv(n->pair[i].i.value);
    if (id < 0 || id >= MAX_CATS) {
      fprintf(stderr, "unknown append category: %.*s\n", n->pair[i].i.value.len,
              n->pair[i].i.value.ptr);
      return -1;
    }
    prt->append_bitmask |= cat_bit_from_id(id);
    prt->append_string[id] = mask;
  }

  return 0;
}

int compile_policy(Program *p, PolicyRunTime *prt) {
  if (p->count < 1) {
    fprintf(stderr, "empty policy\n");
    return -1;
  }

  memset(prt, 0, sizeof *prt);

  for (int i = 0; i < p->count; i++) {
    if (p->stms[i].nparams == 1) {
      if (p->stms[i].params[0].tk.type == PRE) {
        prt->exec_type = 0;
      } else {
        prt->exec_type = 1;
      }

    } else if (p->stms[i].nparams == 2) {
      prt->exec_type = 2;
    }

    if (extract_forbid(&p->stms[i].forbid, prt) != 0) {
      return -1;
    }

    if (extract_redact(&p->stms[i].redact, prt) != 0) {
      return -1;
    }

    if (extract_append(&p->stms[i].append, prt) != 0) {
      return -1;
    }
  }

  return 0;
}
