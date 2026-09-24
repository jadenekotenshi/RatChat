/*
 * der.h -- minimal DER (a strict subset of BER) reader.
 *
 * Just enough to walk an X.509 certificate and decode an ECDSA signature: TLV read/expect,
 * descending into a constructed value, INTEGER/BIT STRING/OID/time primitives, and a
 * SEQUENCE{INTEGER, INTEGER} decoder for ECDSA signatures. Every function takes an explicit
 * [p, end) window and never trusts a length that would read past it. BER's indefinite-length
 * form (a length byte of exactly 0x80) is rejected outright, not just unsupported -- this reader
 * only ever accepts definite lengths.
 */
#ifndef RC_DER_H
#define RC_DER_H

#include "ssh_types.h"
#include "bignum.h"

/* Reads one TLV at *p (primitive or constructed); advances *p past it. *val and *len describe
 * the value bytes (contents only, not the tag/length header). */
int der_read(const u8 **p, const u8 *end, int *tag, const u8 **val, size_t *len);

/* Like der_read, but fails unless the tag equals `want`. */
int der_expect(const u8 **p, const u8 *end, int want, const u8 **val, size_t *len);

/* Descends into a constructed value (SEQUENCE 0x30, SET 0x31, or an explicit context tag such
 * as 0xa0): *inner and *inner_end become a new [p, end) window over its contents. */
int der_enter(const u8 **p, const u8 *end, int want, const u8 **inner, const u8 **inner_end);

/* An INTEGER as an unsigned big-endian magnitude (the DER sign-padding zero byte, if present,
 * is dropped). Refuses a zero-length INTEGER. */
int der_int(const u8 **p, const u8 *end, const u8 **val, size_t *len);

/* A BIT STRING's unused-bit count (0-7) and its value bytes; the leading unused-bits count byte
 * itself is not included in *val or *len. Refuses an empty BIT STRING and an unused-bit count
 * greater than 7. */
int der_bitstring(const u8 **p, const u8 *end, const u8 **val, size_t *len, int *unused_bits);

/* Byte-exact OID comparison. */
int der_oid_eq(const u8 *oid, size_t oid_len, const u8 *want, size_t want_len);

typedef struct { int year, month, day, hour, min, sec; } der_time;

/* UTCTime, RFC 5280's profile only: exactly "YYMMDDHHMMSSZ" (13 bytes) -- seconds and the 'Z'
 * suffix are both required, no fractional seconds, no local-time offset. Two-digit years < 50
 * map to 20YY, >= 50 to 19YY (the classic Y2K rule this format is stuck with). */
int der_utctime(const u8 *val, size_t len, der_time *out);

/* GeneralizedTime, same RFC 5280 profile: exactly "YYYYMMDDHHMMSSZ" (15 bytes). */
int der_generalizedtime(const u8 *val, size_t len, der_time *out);

/* -1 if a < b, 0 if equal, 1 if a > b. A plain field-by-field comparison is a real chronological
 * order here because both times are always UTC by construction. */
int der_time_cmp(const der_time *a, const der_time *b);

/* SEQUENCE { INTEGER r, INTEGER s }, the DER wire form of an ECDSA signature (X9.62 / RFC 5480)
 * -- what TLS's ServerKeyExchange carries, and what ecc.h's ecdsa_verify does not itself parse.
 * r and s must already be bn_init'd; the caller frees them either way. */
int der_ecdsa_sig(const u8 *der, size_t len, bn *r, bn *s);

#endif
