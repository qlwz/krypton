/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

#define DER_INCREMENT 1024
#define OBJ_INCREMENT 4

static void der_free(DER *der);

static int check_end_marker(const char *str, size_t len, int sig_type) {
  switch (sig_type) {
    case PEM_SIG_CERT:
      if (!strncmp(str, "-----END CERTIFICATE-----", len)) return 1;
      break;
    case PEM_SIG_KEY:
      if (!strncmp(str, "-----END PRIVATE KEY-----", len)) return 1;
      break;
    case PEM_SIG_RSA_KEY:
      if (!strncmp(str, "-----END RSA PRIVATE KEY-----", len)) return 1;
      break;
    default:
      assert(0);
  }
  return 0;
}

static int check_begin_marker(const char *str, size_t len, uint8_t *got) {
  if (!strncmp(str, "-----BEGIN CERTIFICATE-----", len)) {
    *got = PEM_SIG_CERT;
    return 1;
  }
  if (!strncmp(str, "-----BEGIN PRIVATE KEY-----", len)) {
    *got = PEM_SIG_KEY;
    return 1;
  }
  if (!strncmp(str, "-----BEGIN RSA PRIVATE KEY-----", len)) {
    *got = PEM_SIG_RSA_KEY;
    return 1;
  }
  return 0;
}

static int add_line(DER *d, size_t *max_len, const uint8_t *buf, size_t len) {
  uint8_t dec[96];
  size_t olen;

  if (!b64_decode(buf, len, dec, &olen)) {
    dprintf(("pem: base64 error\n"));
    return 0;
  }

  if (d->der_len + olen > *max_len) {
    size_t new_len;
    uint8_t *new;

    new_len = *max_len + DER_INCREMENT;
    new = realloc(d->der, new_len);
    if (NULL == new) {
      dprintf(("pem: realloc: %s\n", strerror(errno)));
      return 0;
    }

    d->der = new;
    *max_len = new_len;
  }

  memcpy(d->der + d->der_len, dec, olen);
  d->der_len += olen;

  return 1;
}

static int add_object(PEM *p) {
  if (p->num_obj >= p->max_obj) {
    unsigned int max;
    DER *new;

    max = p->max_obj + OBJ_INCREMENT;

    new = realloc(p->obj, sizeof(*p->obj) * max);
    if (NULL == new) return 0;

    p->obj = new;
    p->max_obj = max;
  }
  return 1;
}

PEM *pem_load(const char *fn, pem_filter_fn flt, void *flt_arg) {
  unsigned int state, cur, i;
#if KR_ENABLE_FILESYSTEM
  /* 2x larger than necesssary */
  char buf[128];
  FILE *f = NULL;
#endif
  const char *pb = NULL;
  size_t der_max_len = 0;
  uint8_t got = 0;
  const char *lb, *le;
  size_t ll;
  PEM *p = NULL;

  /* Allow PEM objects to be passed in the filename. */
  if ((lb = strstr(fn, "-----BEGIN ")) != NULL &&
      (le = strstr(lb + 1, "-----")) != NULL &&
      check_begin_marker(lb, le - lb + 5, &got)) {
    pb = fn;
    fn = "(fn)";
    dprintf(("loading PEM objects from filename\n"));
  } else {
#if KR_ENABLE_FILESYSTEM
    f = fopen(fn, "r");
    if (NULL == f) {
      dprintf(("%s: fopen: %s\n", fn, strerror(errno)));
      goto out_free;
    }
    pb = buf;
#else
    dprintf(("no objects in filename and no fs support\n"));
    goto out;
#endif
  }

#ifdef DEBUG_PEM_LOAD
  dprintf(("loading PEM objects from %s\n", fn));
#endif
  p = calloc(1, sizeof(*p));
  if (NULL == p) {
    goto out;
  }

  state = cur = 0;
  lb = pb;
  while (1) {
#if KR_ENABLE_FILESYSTEM
    if (pb == buf) {
      if (!fgets(buf, sizeof(buf), f)) break;
      lb = buf;
    }
#endif

    /* Find next line, trim whitespace. */
    while (*lb != '\0' && isspace((int) *lb)) lb++;
    if (*lb == '\0') break;
    le = strchr(lb, '\n');
    if (le == NULL) break;
    while (le > lb && isspace((int) *le)) le--;
    le++;
    ll = (le - lb);
#ifdef DEBUG_PEM_LOAD
    dprintf(("state %d, lb = %p, le = %p, ll = %d, '%.*s'\n", state, lb, le,
             (int) ll, (int) ll, lb));
#endif

    switch (state) {
      case 0: /* begin marker */
        if (check_begin_marker(lb, ll, &got)) {
          if (!add_object(p)) goto out_free;
          cur = p->num_obj++;
          p->obj[cur].der_type = got;
          p->obj[cur].der_len = 0;
          p->obj[cur].der = NULL;
          der_max_len = 0;
          state = 1;
        }
        break;
      case 1: /* content*/
        if (check_end_marker(lb, ll, p->obj[cur].der_type)) {
          enum pem_filter_result keep = flt(&p->obj[cur], got, flt_arg);
          if (keep != PEM_FILTER_NO) {
            p->tot_len += p->obj[cur].der_len;
            if (keep == PEM_FILTER_YES_AND_STOP) {
              goto out;
            }
          } else { /* Rejected by filter */
            der_free(&p->obj[cur]);
            cur = --p->num_obj;
          }
          state = 0;
#ifdef DEBUG_PEM_LOAD
          dprintf(("%s: Loaded %d byte PEM\n", fn, p->obj[cur].der_len));
          ber_dump(p->obj[cur].der, p->obj[cur].der_len);
#endif
          break;
        }

        if (!add_line(&p->obj[cur], &der_max_len, (const uint8_t *) lb, ll)) {
          dprintf(("%s: Corrupted key or cert\n", fn));
          goto out_free;
        }

        break;
      default:
        break;
    }
    lb = le;
  }

  if (state != 0) {
    dprintf(("%s: no end marker\n", fn));
    goto out_free;
  }

  if (p->num_obj < 1) {
    dprintf(("%s: no objects in file\n", fn));
  }

  goto out;

out_free:
  if (p != NULL) {
    for (i = 0; i < p->num_obj; i++) {
      free(p->obj[i].der);
    }
    free(p->obj);
    free(p);
    p = NULL;
  }
out:
#if KR_ENABLE_FILESYSTEM
  if (f != NULL) fclose(f);
#endif
  return p;
}

static enum pem_filter_result pem_type_filter(const DER *obj, int type,
                                              void *arg) {
  int type_mask = *((int *) arg);
  (void) obj;
  return (type & type_mask ? PEM_FILTER_YES : PEM_FILTER_NO);
}

PEM *pem_load_types(const char *fn, int type_mask) {
  return pem_load(fn, pem_type_filter, &type_mask);
}

static void der_free(DER *der) {
  free(der->der);
}

void pem_free(PEM *p) {
  if (p) {
    unsigned int i;
    for (i = 0; i < p->num_obj; i++) {
      der_free(&p->obj[i]);
    }
    free(p->obj);
    free(p);
  }
}
