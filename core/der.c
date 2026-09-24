#include "der.h"
#include <string.h>

/* Tags are read as a single byte -- the high-tag-number form (low 5 bits of the first byte all
 * set) never comes up in an X.509 certificate's own structure or in a DER ECDSA signature, the
 * only two things this reader is for, so it is not implemented. */

int der_read(const u8 **p, const u8 *end, int *tag, const u8 **val, size_t *len)
{
    const u8 *q = *p;
    size_t l;
    if (end - q < 2) return -1;
    *tag = q[0];
    l = q[1];
    q += 2;
    if (l & 0x80) {
        int nb = (int)(l & 0x7f);
        /* nb == 0 is BER's indefinite-length marker (0x80 alone) -- refused, not just unhandled. */
        if (nb == 0 || nb > 4 || end - q < nb) return -1;
        l = 0;
        while (nb--) l = (l << 8) | *q++;
    }
    if ((size_t)(end - q) < l) return -1;
    *val = q; *len = l;
    *p = q + l;
    return 0;
}

int der_expect(const u8 **p, const u8 *end, int want, const u8 **val, size_t *len)
{
    int tag;
    if (der_read(p, end, &tag, val, len) != 0 || tag != want) return -1;
    return 0;
}

int der_enter(const u8 **p, const u8 *end, int want, const u8 **inner, const u8 **inner_end)
{
    const u8 *val;
    size_t len;
    if (der_expect(p, end, want, &val, &len) != 0) return -1;
    *inner = val;
    *inner_end = val + len;
    return 0;
}

int der_int(const u8 **p, const u8 *end, const u8 **val, size_t *len)
{
    if (der_expect(p, end, 0x02, val, len) != 0 || *len == 0) return -1;
    while (*len > 1 && **val == 0) { (*val)++; (*len)--; }
    return 0;
}

int der_bitstring(const u8 **p, const u8 *end, const u8 **val, size_t *len, int *unused_bits)
{
    const u8 *v;
    size_t l;
    if (der_expect(p, end, 0x03, &v, &l) != 0 || l == 0 || v[0] > 7) return -1;
    *unused_bits = v[0];
    *val = v + 1;
    *len = l - 1;
    return 0;
}

int der_oid_eq(const u8 *oid, size_t oid_len, const u8 *want, size_t want_len)
{
    return oid_len == want_len && memcmp(oid, want, oid_len) == 0;
}

static int d2(const u8 *p, int *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') return -1;
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return 0;
}

static int valid_ymdhms(int mo, int dd, int hh, int mi, int ss)
{
    return mo >= 1 && mo <= 12 && dd >= 1 && dd <= 31 && hh <= 23 && mi <= 59 && ss <= 59;
}

int der_utctime(const u8 *val, size_t len, der_time *out)
{
    int yy, mo, dd, hh, mi, ss;
    if (len != 13 || val[12] != 'Z') return -1;
    if (d2(val, &yy) || d2(val + 2, &mo) || d2(val + 4, &dd) ||
        d2(val + 6, &hh) || d2(val + 8, &mi) || d2(val + 10, &ss)) return -1;
    if (!valid_ymdhms(mo, dd, hh, mi, ss)) return -1;
    out->year = yy < 50 ? 2000 + yy : 1900 + yy;                 /* RFC 5280's UTCTime rule */
    out->month = mo; out->day = dd; out->hour = hh; out->min = mi; out->sec = ss;
    return 0;
}

int der_generalizedtime(const u8 *val, size_t len, der_time *out)
{
    int c, yy, mo, dd, hh, mi, ss;
    if (len != 15 || val[14] != 'Z') return -1;
    if (d2(val, &c) || d2(val + 2, &yy) || d2(val + 4, &mo) || d2(val + 6, &dd) ||
        d2(val + 8, &hh) || d2(val + 10, &mi) || d2(val + 12, &ss)) return -1;
    if (!valid_ymdhms(mo, dd, hh, mi, ss)) return -1;
    out->year = c * 100 + yy; out->month = mo; out->day = dd; out->hour = hh; out->min = mi; out->sec = ss;
    return 0;
}

int der_time_cmp(const der_time *a, const der_time *b)
{
    if (a->year != b->year) return a->year < b->year ? -1 : 1;
    if (a->month != b->month) return a->month < b->month ? -1 : 1;
    if (a->day != b->day) return a->day < b->day ? -1 : 1;
    if (a->hour != b->hour) return a->hour < b->hour ? -1 : 1;
    if (a->min != b->min) return a->min < b->min ? -1 : 1;
    if (a->sec != b->sec) return a->sec < b->sec ? -1 : 1;
    return 0;
}

int der_ecdsa_sig(const u8 *der, size_t len, bn *r, bn *s)
{
    const u8 *p = der, *end = der + len, *seq, *seq_end, *rv, *sv;
    size_t rl, sl;
    if (der_enter(&p, end, 0x30, &seq, &seq_end) != 0 || p != end) return -1;
    if (der_int(&seq, seq_end, &rv, &rl) != 0) return -1;
    if (der_int(&seq, seq_end, &sv, &sl) != 0) return -1;
    if (seq != seq_end) return -1;                               /* trailing garbage in the SEQUENCE */
    if (bn_from_bytes(r, rv, rl) != 0) return -1;
    if (bn_from_bytes(s, sv, sl) != 0) return -1;
    return 0;
}
