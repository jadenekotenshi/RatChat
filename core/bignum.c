#include <stdlib.h>
#include <string.h>
#include "bignum.h"

typedef long long i64;

void bn_init(bn *a) { a->d = NULL; a->n = a->cap = 0; }

void bn_free(bn *a)
{
    if (a->d) { ssh_wipe(a->d, (size_t)a->cap * sizeof(u32)); free(a->d); }
    bn_init(a);
}

static int bn_reserve(bn *a, int limbs)
{
    u32 *nd;
    int ncap;
    if (limbs <= a->cap) return 0;
    ncap = a->cap ? a->cap : 4;
    while (ncap < limbs) ncap *= 2;
    nd = (u32 *)calloc((size_t)ncap, sizeof(u32));
    if (!nd) return -1;
    if (a->d) { memcpy(nd, a->d, (size_t)a->n * sizeof(u32)); ssh_wipe(a->d, (size_t)a->cap * sizeof(u32)); free(a->d); }
    a->d = nd; a->cap = ncap;
    return 0;
}

static void bn_trim(bn *a) { while (a->n > 0 && a->d[a->n - 1] == 0) a->n--; }

int bn_set_u32(bn *a, u32 v)
{
    if (bn_reserve(a, 1) < 0) return -1;
    a->d[0] = v;
    a->n = v ? 1 : 0;
    return 0;
}

int bn_copy(bn *r, const bn *a)
{
    if (r == a) return 0;
    if (bn_reserve(r, a->n ? a->n : 1) < 0) return -1;
    if (a->n) memcpy(r->d, a->d, (size_t)a->n * sizeof(u32));
    r->n = a->n;
    return 0;
}

int bn_from_bytes(bn *a, const u8 *be, size_t len)
{
    int limbs = (int)((len + 3) / 4), i;
    if (bn_reserve(a, limbs ? limbs : 1) < 0) return -1;
    memset(a->d, 0, (size_t)a->cap * sizeof(u32));
    for (i = 0; i < (int)len; i++) {                      /* byte i from the end goes to limb i/4 */
        size_t pos = len - 1 - (size_t)i;
        a->d[i / 4] |= (u32)be[pos] << (8 * (i % 4));
    }
    a->n = limbs;
    bn_trim(a);
    return 0;
}

int bn_bits(const bn *a)
{
    u32 top;
    int b = 0;
    if (a->n == 0) return 0;
    top = a->d[a->n - 1];
    while (top) { b++; top >>= 1; }
    return (a->n - 1) * 32 + b;
}

int bn_to_bytes(const bn *a, u8 *out, size_t len)
{
    size_t need = (size_t)(bn_bits(a) + 7) / 8, i;
    if (need > len) return -1;
    memset(out, 0, len);
    for (i = 0; i < need; i++) out[len - 1 - i] = (u8)(a->d[i / 4] >> (8 * (i % 4)));
    return 0;
}

int bn_bit(const bn *a, int i)
{
    if (i < 0 || i / 32 >= a->n) return 0;
    return (int)((a->d[i / 32] >> (i % 32)) & 1);
}

int bn_is_zero(const bn *a) { return a->n == 0; }
int bn_is_odd(const bn *a) { return a->n > 0 && (a->d[0] & 1); }

int bn_cmp(const bn *a, const bn *b)
{
    int i;
    if (a->n != b->n) return a->n > b->n ? 1 : -1;
    for (i = a->n - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return a->d[i] > b->d[i] ? 1 : -1;
    return 0;
}

int bn_add(bn *r, const bn *a, const bn *b)
{
    int n = a->n > b->n ? a->n : b->n, i;
    u64 carry = 0, s;
    u32 *tmp;
    tmp = (u32 *)calloc((size_t)n + 1, sizeof(u32));
    if (!tmp) return -1;
    for (i = 0; i < n; i++) {
        s = carry;
        if (i < a->n) s += a->d[i];
        if (i < b->n) s += b->d[i];
        tmp[i] = (u32)s;
        carry = s >> 32;
    }
    tmp[n] = (u32)carry;
    if (bn_reserve(r, n + 1) < 0) { free(tmp); return -1; }
    memcpy(r->d, tmp, (size_t)(n + 1) * sizeof(u32));
    r->n = n + 1;
    bn_trim(r);
    ssh_wipe(tmp, ((size_t)n + 1) * sizeof(u32));
    free(tmp);
    return 0;
}

int bn_sub(bn *r, const bn *a, const bn *b)
{
    int i;
    i64 borrow = 0, t;
    u32 *tmp;
    if (bn_cmp(a, b) < 0) return -1;
    tmp = (u32 *)calloc((size_t)(a->n ? a->n : 1), sizeof(u32));
    if (!tmp) return -1;
    for (i = 0; i < a->n; i++) {
        t = (i64)a->d[i] - borrow - (i < b->n ? (i64)b->d[i] : 0);
        borrow = t < 0 ? 1 : 0;
        tmp[i] = (u32)t;
    }
    if (bn_reserve(r, a->n ? a->n : 1) < 0) { free(tmp); return -1; }
    memcpy(r->d, tmp, (size_t)a->n * sizeof(u32));
    r->n = a->n;
    bn_trim(r);
    ssh_wipe(tmp, (size_t)(a->n ? a->n : 1) * sizeof(u32));
    free(tmp);
    return 0;
}

int bn_mul(bn *r, const bn *a, const bn *b)
{
    int i, j, n = a->n + b->n;
    u32 *tmp;
    u64 carry, v;
    if (a->n == 0 || b->n == 0) return bn_set_u32(r, 0);
    tmp = (u32 *)calloc((size_t)n, sizeof(u32));
    if (!tmp) return -1;
    for (i = 0; i < a->n; i++) {
        carry = 0;
        for (j = 0; j < b->n; j++) {
            v = (u64)a->d[i] * b->d[j] + tmp[i + j] + carry;
            tmp[i + j] = (u32)v;
            carry = v >> 32;
        }
        tmp[i + b->n] = (u32)carry;
    }
    if (bn_reserve(r, n) < 0) { free(tmp); return -1; }
    memcpy(r->d, tmp, (size_t)n * sizeof(u32));
    r->n = n;
    bn_trim(r);
    ssh_wipe(tmp, (size_t)n * sizeof(u32));
    free(tmp);
    return 0;
}

int bn_shl(bn *r, const bn *a, int bits)
{
    int limbs = bits / 32, sh = bits % 32, i, n = a->n + limbs + 1;
    u32 *tmp;
    if (a->n == 0) return bn_set_u32(r, 0);
    tmp = (u32 *)calloc((size_t)n, sizeof(u32));
    if (!tmp) return -1;
    for (i = 0; i < a->n; i++) {
        tmp[i + limbs] |= a->d[i] << sh;
        if (sh) tmp[i + limbs + 1] |= a->d[i] >> (32 - sh);
    }
    if (bn_reserve(r, n) < 0) { free(tmp); return -1; }
    memcpy(r->d, tmp, (size_t)n * sizeof(u32));
    r->n = n;
    bn_trim(r);
    free(tmp);
    return 0;
}

int bn_shr(bn *r, const bn *a, int bits)
{
    int limbs = bits / 32, sh = bits % 32, i, n = a->n - limbs;
    u32 *tmp;
    if (n <= 0) return bn_set_u32(r, 0);
    tmp = (u32 *)calloc((size_t)n, sizeof(u32));
    if (!tmp) return -1;
    for (i = 0; i < n; i++) {
        tmp[i] = a->d[i + limbs] >> sh;
        if (sh && i + limbs + 1 < a->n) tmp[i] |= a->d[i + limbs + 1] << (32 - sh);
    }
    if (bn_reserve(r, n) < 0) { free(tmp); return -1; }
    memcpy(r->d, tmp, (size_t)n * sizeof(u32));
    r->n = n;
    bn_trim(r);
    free(tmp);
    return 0;
}

/* Knuth, TAOCP vol. 2, 4.3.1 Algorithm D (as in Hacker's Delight "divmnu"). */
int bn_divmod(bn *q, bn *r, const bn *a, const bn *b)
{
    int m = a->n, n = b->n, s, i, j;
    u32 *un = NULL, *vn = NULL, *qq = NULL;
    u64 qhat, rhat, p = 0, base = 0x100000000ULL;  /* p: always set before read (inner loop runs
                                                      * n>=2 times here); m68k's dataflow analysis
                                                      * can't see that across the loop back-edge */
    i64 t, k;
    int rc = -1;

    if (n == 0) return -1;
    if (m < n || bn_cmp(a, b) < 0) {                         /* quotient 0, remainder a */
        if (r && bn_copy(r, a) < 0) return -1;
        if (q && bn_set_u32(q, 0) < 0) return -1;
        return 0;
    }
    if (n == 1) {                                            /* short division */
        u64 rem = 0;
        qq = (u32 *)calloc((size_t)m, sizeof(u32));
        if (!qq) return -1;
        for (j = m - 1; j >= 0; j--) {
            u64 cur = (rem << 32) | a->d[j];
            qq[j] = (u32)(cur / b->d[0]);
            rem = cur % b->d[0];
        }
        if (q) { if (bn_reserve(q, m) < 0) goto fail; memcpy(q->d, qq, (size_t)m * sizeof(u32)); q->n = m; bn_trim(q); }
        if (r && bn_set_u32(r, (u32)rem) < 0) goto fail;
        free(qq);
        return 0;
    }
    s = 0;
    { u32 top = b->d[n - 1]; while (!(top & 0x80000000UL)) { top <<= 1; s++; } }
    vn = (u32 *)calloc((size_t)n, sizeof(u32));
    un = (u32 *)calloc((size_t)m + 1, sizeof(u32));
    qq = (u32 *)calloc((size_t)(m - n + 1), sizeof(u32));
    if (!vn || !un || !qq) goto fail;
    for (i = n - 1; i > 0; i--) vn[i] = s ? (b->d[i] << s) | (b->d[i - 1] >> (32 - s)) : b->d[i];
    vn[0] = b->d[0] << s;
    un[m] = s ? a->d[m - 1] >> (32 - s) : 0;
    for (i = m - 1; i > 0; i--) un[i] = s ? (a->d[i] << s) | (a->d[i - 1] >> (32 - s)) : a->d[i];
    un[0] = a->d[0] << s;

    for (j = m - n; j >= 0; j--) {
        qhat = (((u64)un[j + n] << 32) | un[j + n - 1]) / vn[n - 1];
        rhat = (((u64)un[j + n] << 32) | un[j + n - 1]) - qhat * vn[n - 1];
        while (qhat >= base || qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2])) {
            qhat--;
            rhat += vn[n - 1];
            if (rhat >= base) break;
        }
        k = 0;
        for (i = 0; i < n; i++) {                            /* multiply and subtract */
            p = qhat * vn[i];
            t = (i64)un[i + j] - k - (i64)(p & 0xffffffffULL);
            un[i + j] = (u32)t;
            k = (i64)(p >> 32) - (t >> 32);
        }
        t = (i64)un[j + n] - k;
        un[j + n] = (u32)t;
        qq[j] = (u32)qhat;
        if (t < 0) {                                         /* qhat was one too large: add back */
            u64 c = 0, sum;
            qq[j]--;
            for (i = 0; i < n; i++) {
                sum = (u64)un[i + j] + vn[i] + c;
                un[i + j] = (u32)sum;
                c = sum >> 32;
            }
            un[j + n] += (u32)c;
        }
    }
    if (q) { if (bn_reserve(q, m - n + 1) < 0) goto fail; memcpy(q->d, qq, (size_t)(m - n + 1) * sizeof(u32)); q->n = m - n + 1; bn_trim(q); }
    if (r) {
        if (bn_reserve(r, n) < 0) goto fail;
        for (i = 0; i < n; i++) r->d[i] = s ? (un[i] >> s) | (un[i + 1] << (32 - s)) : un[i];
        r->n = n;
        bn_trim(r);
    }
    rc = 0;
fail:
    if (un) { ssh_wipe(un, ((size_t)m + 1) * sizeof(u32)); free(un); }
    if (vn) { ssh_wipe(vn, (size_t)n * sizeof(u32)); free(vn); }
    if (qq) free(qq);
    return rc;
}

int bn_mod(bn *r, const bn *a, const bn *m) { return bn_divmod(NULL, r, a, m); }

int bn_addmod(bn *r, const bn *a, const bn *b, const bn *m)
{
    if (bn_add(r, a, b) < 0) return -1;
    if (bn_cmp(r, m) >= 0) return bn_sub(r, r, m);
    return 0;
}

int bn_submod(bn *r, const bn *a, const bn *b, const bn *m)
{
    bn t;
    int rc;
    if (bn_cmp(a, b) >= 0) return bn_sub(r, a, b);
    bn_init(&t);
    rc = bn_add(&t, a, m) < 0 ? -1 : bn_sub(r, &t, b);
    bn_free(&t);
    return rc;
}

int bn_mulmod(bn *r, const bn *a, const bn *b, const bn *m)
{
    bn t;
    int rc;
    bn_init(&t);
    rc = (bn_mul(&t, a, b) < 0 || bn_mod(r, &t, m) < 0) ? -1 : 0;
    bn_free(&t);
    return rc;
}

/* ---------------- Montgomery exponentiation (odd modulus) ---------------- */

static u32 mont_m0inv(u32 m0)                               /* -m0^-1 mod 2^32, by Newton iteration */
{
    u32 x = m0;                                              /* correct to 3 bits for odd m0 */
    x *= 2 - m0 * x; x *= 2 - m0 * x; x *= 2 - m0 * x; x *= 2 - m0 * x;
    return (u32)(0 - x);
}

/* out = a*b*R^-1 mod m, all n limbs; t is scratch of n+2 limbs; out may alias a or b. */
static void mont_mul(u32 *out, const u32 *a, const u32 *b, const u32 *m, int n, u32 m0inv, u32 *t)
{
    int i, j;
    u64 v, carry;
    u32 mm;
    memset(t, 0, ((size_t)n + 2) * sizeof(u32));
    for (i = 0; i < n; i++) {
        carry = 0;
        for (j = 0; j < n; j++) {
            v = (u64)a[j] * b[i] + t[j] + carry;
            t[j] = (u32)v;
            carry = v >> 32;
        }
        v = (u64)t[n] + carry;
        t[n] = (u32)v;
        t[n + 1] = (u32)(v >> 32);
        mm = t[0] * m0inv;
        v = (u64)mm * m[0] + t[0];
        carry = v >> 32;
        for (j = 1; j < n; j++) {
            v = (u64)mm * m[j] + t[j] + carry;
            t[j - 1] = (u32)v;
            carry = v >> 32;
        }
        v = (u64)t[n] + carry;
        t[n - 1] = (u32)v;
        t[n] = t[n + 1] + (u32)(v >> 32);
    }
    /* t[0..n] holds the result, possibly >= m: subtract once if so */
    {
        int ge = t[n] != 0;
        if (!ge) {
            for (j = n - 1; j >= 0; j--) {
                if (t[j] != m[j]) { ge = t[j] > m[j]; break; }
                if (j == 0) ge = 1;
            }
        }
        if (ge) {
            i64 borrow = 0, d;
            for (j = 0; j < n; j++) {
                d = (i64)t[j] - m[j] - borrow;
                borrow = d < 0 ? 1 : 0;
                out[j] = (u32)d;
            }
        } else {
            for (j = 0; j < n; j++) out[j] = t[j];
        }
    }
}

static int modexp_plain(bn *r, const bn *base, const bn *exp, const bn *mod)
{
    bn result, b, tmp;
    int i, rc = -1;
    bn_init(&result); bn_init(&b); bn_init(&tmp);
    if (bn_set_u32(&result, 1) < 0 || bn_mod(&b, base, mod) < 0 || bn_mod(&result, &result, mod) < 0) goto out;
    for (i = bn_bits(exp) - 1; i >= 0; i--) {
        if (bn_mulmod(&tmp, &result, &result, mod) < 0 || bn_copy(&result, &tmp) < 0) goto out;
        if (bn_bit(exp, i) && (bn_mulmod(&tmp, &result, &b, mod) < 0 || bn_copy(&result, &tmp) < 0)) goto out;
    }
    rc = bn_copy(r, &result);
out:
    bn_free(&result); bn_free(&b); bn_free(&tmp);
    return rc;
}

int bn_modexp(bn *r, const bn *base, const bn *exp, const bn *mod)
{
    int n = mod->n, i, j, top, rc = -1;
    u32 m0inv;
    u32 *table = NULL, *acc = NULL, *scratch = NULL, *one = NULL;
    bn x, rr;
    if (n == 0) return -1;
    if (bn_bits(mod) == 1) return bn_set_u32(r, 0);
    if (!bn_is_odd(mod)) return modexp_plain(r, base, exp, mod);
    if (bn_is_zero(exp)) return bn_set_u32(r, 1);

    bn_init(&x); bn_init(&rr);
    table = (u32 *)calloc((size_t)16 * (size_t)n, sizeof(u32));
    acc = (u32 *)calloc((size_t)n, sizeof(u32));
    one = (u32 *)calloc((size_t)n, sizeof(u32));
    scratch = (u32 *)calloc((size_t)n + 2, sizeof(u32));
    if (!table || !acc || !one || !scratch) goto out;
    m0inv = mont_m0inv(mod->d[0]);

    /* rr = R mod m gives Montgomery(1); base_m = base*R mod m = mont(base, R^2) -- do it with plain division */
    { bn one_bn, shifted;
      bn_init(&one_bn); bn_init(&shifted);
      if (bn_set_u32(&one_bn, 1) < 0 || bn_shl(&shifted, &one_bn, 32 * n) < 0 || bn_mod(&rr, &shifted, mod) < 0) {
          bn_free(&one_bn); bn_free(&shifted); goto out;
      }
      bn_free(&shifted);
      if (bn_mod(&x, base, mod) < 0 || bn_shl(&shifted, &x, 32 * n) < 0 || bn_mod(&x, &shifted, mod) < 0) {
          bn_free(&one_bn); bn_free(&shifted); goto out;
      }
      bn_free(&one_bn); bn_free(&shifted);
    }
    memset(table, 0, (size_t)16 * (size_t)n * sizeof(u32));
    for (i = 0; i < rr.n; i++) table[i] = rr.d[i];                          /* table[0] = 1 in Montgomery form */
    for (i = 0; i < x.n; i++) table[n + i] = x.d[i];                        /* table[1] = base */
    for (i = 2; i < 16; i++) mont_mul(&table[i * n], &table[(i - 1) * n], &table[n], mod->d, n, m0inv, scratch);

    top = ((bn_bits(exp) + 3) / 4) * 4;                                     /* process the exponent 4 bits at a time */
    memcpy(acc, table, (size_t)n * sizeof(u32));                           /* acc = 1 */
    for (i = top - 4; i >= 0; i -= 4) {
        int w = bn_bit(exp, i) | (bn_bit(exp, i + 1) << 1) | (bn_bit(exp, i + 2) << 2) | (bn_bit(exp, i + 3) << 3);
        for (j = 0; j < 4; j++) mont_mul(acc, acc, acc, mod->d, n, m0inv, scratch);
        if (w) mont_mul(acc, acc, &table[w * n], mod->d, n, m0inv, scratch);
    }
    one[0] = 1;
    mont_mul(acc, acc, one, mod->d, n, m0inv, scratch);                     /* leave Montgomery form */
    if (bn_reserve(r, n) < 0) goto out;
    memcpy(r->d, acc, (size_t)n * sizeof(u32));
    r->n = n;
    bn_trim(r);
    rc = 0;
out:
    if (table) { ssh_wipe(table, (size_t)16 * (size_t)n * sizeof(u32)); free(table); }
    if (acc) { ssh_wipe(acc, (size_t)n * sizeof(u32)); free(acc); }
    free(one); free(scratch);
    bn_free(&x); bn_free(&rr);
    return rc;
}

int bn_modinv_prime(bn *r, const bn *a, const bn *p)
{
    bn e, two;
    int rc = -1;
    bn_init(&e); bn_init(&two);
    if (bn_set_u32(&two, 2) < 0 || bn_sub(&e, p, &two) < 0) goto out;
    rc = bn_modexp(r, a, &e, p);
out:
    bn_free(&e); bn_free(&two);
    return rc;
}
