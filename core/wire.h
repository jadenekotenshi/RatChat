#ifndef SSH_WIRE_H
#define SSH_WIRE_H
#include "ssh_types.h"

/* Growable byte buffer.  Allocation failure is sticky (`oom`) so builders can
 * chain puts and check once. */
typedef struct { u8 *p; size_t len, cap; int oom; } sbuf;

void sb_init(sbuf *b);
void sb_free(sbuf *b);                    /* wipes, then frees */
void sb_clear(sbuf *b);                   /* wipes contents, keeps capacity */
int  sb_reserve(sbuf *b, size_t extra);
int  sb_put(sbuf *b, const void *d, size_t n);
int  sb_put_u8(sbuf *b, u8 v);
int  sb_put_u32(sbuf *b, u32 v);
int  sb_put_u64(sbuf *b, u64 v);
int  sb_put_str(sbuf *b, const void *d, size_t n);      /* SSH "string" */
int  sb_put_cstr(sbuf *b, const char *s);
int  sb_put_mpint(sbuf *b, const u8 *be, size_t n);     /* unsigned big-endian magnitude */
void sb_consume(sbuf *b, size_t n);                     /* drop n bytes from the front */

/* Bounds-checked reader; any overrun sets `err` and yields zeros/NULL. */
typedef struct { const u8 *p; size_t len, pos; int err; } sreader;

void        sr_init(sreader *r, const u8 *p, size_t len);
u8          sr_u8(sreader *r);
u32         sr_u32(sreader *r);
u64         sr_u64(sreader *r);
const u8   *sr_str(sreader *r, size_t *len);            /* points into the input */
const u8   *sr_bytes(sreader *r, size_t n);
size_t      sr_left(const sreader *r);

/* base64 (RFC 4648).  Encode returns length, or -1 if out is too small. */
int b64_encode(const u8 *in, size_t n, char *out, size_t outsz, int pad);
/* Decode ignores ASCII whitespace; returns byte count or -1 on bad input. */
int b64_decode(const char *in, size_t n, u8 *out, size_t outsz);

#endif
