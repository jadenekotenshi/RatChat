/*
 * test_prims.c -- does this compiler + CPU do 64-bit and Curve25519 field arithmetic correctly?
 *
 * Written when core/nacl.c's X25519/Ed25519 passed everywhere except real m68k hardware (a
 * Previous-emulated 68040 running gcc 2.7.2's code), where they produced silently wrong answers:
 * no crash, no compiler complaint, and nothing in the source that reads as platform-dependent.
 * test_crypto only says "x25519 mismatch"; this takes the arithmetic apart so a failing machine
 * says WHICH primitive is wrong.  In order:
 *
 *   1. the plain signed 64-bit operations nacl.c leans on (arithmetic right shifts of negative
 *      values by constant and variable counts, 64-bit multiplies, masks, casts...), each run over
 *      a table of operands and reported as one hash line per operation;
 *   2. nacl.c's own static field primitives (pack/unpack, car25519, fmul, fsqr, inv25519,
 *      pow2523, sel25519) on fixed inputs, printing the raw limbs;
 *   3. the group-level and public entry points (ge_scalarbase, modL, sha512, X25519, Ed25519).
 *
 * Every line is compared with tests/prims_ref.h, captured on a host where the whole suite
 * passes, so no independent oracle is needed:
 *
 *     build/test_prims        check this machine against the reference (a BAD line shows both)
 *     build/test_prims -v     also list every operand/result pair, for diffing two machines
 *     build/test_prims -g     print a fresh prims_ref.h (only if nacl.c's internals change)
 *
 * nacl.c is #included so its static functions are reachable; its five public symbols are renamed
 * out of the way so this can link against core/nacl.o like every other test does.
 */
#include <stdio.h>
#include <string.h>

#define x25519 prims_x25519
#define x25519_base prims_x25519_base
#define ed25519_keypair prims_ed25519_keypair
#define ed25519_sign prims_ed25519_sign
#define ed25519_verify prims_ed25519_verify
#include "../core/nacl.c"

#include "prims_ref.h"

#define NELEM(a) ((int)(sizeof(a) / sizeof((a)[0])))

static int gen_mode, verbose, nlines, nbad, nnote, ndetail, tolerate;

/* Raw constant-16 arithmetic shifts: broken by gcc 2.7.2's m68k backend (see the SAR16 comment in
 * nacl.c), worked around there, so on that compiler these are reported as NOTEs, not failures.
 * Everything that USES the shift -- and the SAR16 versions of it -- is still checked strictly. */
static int known_compiler_bug(const char *name)
{
    return strcmp(name, "sar16") == 0 || strcmp(name, "carry") == 0 || strcmp(name, "carryc") == 0;
}

/* i64 -> 16 hex digits without doing any 64-bit arithmetic (that is what is under test). */
static void hex64(char *out, i64 v)
{
    u8 b[8];
    u32 probe = 1;
    int i, le = (*(u8 *)&probe == 1);
    memcpy(b, &v, 8);
    for (i = 0; i < 8; i++) sprintf(out + 2 * i, "%02x", b[le ? 7 - i : i]);
}

static int put_line(const char *line)
{
    int ok = 1;
    if (gen_mode) {
        printf("  \"%s\",\n", line);
    } else if (nlines < REF_COUNT && strcmp(line, ref_lines[nlines]) == 0) {
        if (verbose) printf("ok   %s\n", line);
    } else if (tolerate) {
        ok = 0;
        nnote++;
        printf("NOTE known gcc 2.7.2 m68k bug (worked around in nacl.c), got: %s\n", line);
    } else {
        ok = 0;
        nbad++;
        printf("BAD  got  %s\n", line);
        if (nlines < REF_COUNT) printf("     want %s\n", ref_lines[nlines]);
        else printf("     want (no reference line -- regenerate prims_ref.h)\n");
    }
    nlines++;
    return ok;
}

static u32 fnv(u32 h, const char *s)
{
    while (*s) { h ^= (u8)*s++; h *= 16777619UL; }
    return h;
}

/* -------------------------- 1. 64-bit operations -------------------------- */

typedef i64 (*unop_t)(i64);
typedef i64 (*binop_t)(i64, i64);

/* Full-range operands (kept within +-2^62 so + and - can never overflow). */
static const i64 wide[] = {
    0LL, 1LL, -1LL, 2LL, -2LL, 0xffLL, 0x100LL, -0x100LL, 0xffffLL, 0x10000LL, -0x10000LL,
    0x1ffffLL, -0x1ffffLL, 0x7fffffffLL, -0x7fffffffLL, 0x80000000LL, -0x80000000LL,
    0xffffffffLL, 0x100000000LL, -0x100000000LL, 0xfffffffffLL, -0xfffffffffLL,
    0x1234567800LL, -0x1234567800LL, 0x123456789abcdefLL, -0x123456789abcdefLL,
    0x3fffffffffffffffLL, -0x3fffffffffffffffLL
};
/* Moderate operands (|x| < 2^31 so a product always fits in 63 bits). */
static const i64 moder[] = {
    0LL, 1LL, -1LL, 2LL, 37LL, 38LL, 255LL, 256LL, 0xffffLL, 0x10000LL, -0xffffLL, 0x1ffffLL,
    -0x1ffffLL, 0x7fffffffLL, -0x7fffffffLL, 0x12345LL, -0x54321LL, 0xffedLL, 0x7fffLL, -32768LL
};
static const i64 sar_counts[] = { 0, 1, 7, 8, 15, 16, 17, 24, 31, 32, 33, 47, 48, 63 };
static const i64 shl_counts[] = { 0, 1, 8, 15, 16, 17, 31, 32, 33, 40, 47 };

/* Every constant shift count 1..63, three ways: arithmetic right (signed), logical right, left. */
#define SHIFTS(n) \
    static i64 op_sar##n(i64 a) { return a >> n; } \
    static i64 op_shr##n(i64 a) { return (i64)((u64)a >> n); } \
    static i64 op_shl##n(i64 a) { return (i64)((u64)a << n); }
SHIFTS(1) SHIFTS(2) SHIFTS(3) SHIFTS(4) SHIFTS(5) SHIFTS(6) SHIFTS(7) SHIFTS(8) SHIFTS(9)
SHIFTS(10) SHIFTS(11) SHIFTS(12) SHIFTS(13) SHIFTS(14) SHIFTS(15) SHIFTS(16) SHIFTS(17)
SHIFTS(18) SHIFTS(19) SHIFTS(20) SHIFTS(21) SHIFTS(22) SHIFTS(23) SHIFTS(24) SHIFTS(25)
SHIFTS(26) SHIFTS(27) SHIFTS(28) SHIFTS(29) SHIFTS(30) SHIFTS(31) SHIFTS(32) SHIFTS(33)
SHIFTS(34) SHIFTS(35) SHIFTS(36) SHIFTS(37) SHIFTS(38) SHIFTS(39) SHIFTS(40) SHIFTS(41)
SHIFTS(42) SHIFTS(43) SHIFTS(44) SHIFTS(45) SHIFTS(46) SHIFTS(47) SHIFTS(48) SHIFTS(49)
SHIFTS(50) SHIFTS(51) SHIFTS(52) SHIFTS(53) SHIFTS(54) SHIFTS(55) SHIFTS(56) SHIFTS(57)
SHIFTS(58) SHIFTS(59) SHIFTS(60) SHIFTS(61) SHIFTS(62) SHIFTS(63)

typedef struct { const char *name; unop_t f; } named_un;
#define SHROW(n) { "sar" #n, op_sar##n }, { "shr" #n, op_shr##n }, { "shl" #n, op_shl##n },
static const named_un shift_ops[] = {
    SHROW(1) SHROW(2) SHROW(3) SHROW(4) SHROW(5) SHROW(6) SHROW(7) SHROW(8) SHROW(9) SHROW(10)
    SHROW(11) SHROW(12) SHROW(13) SHROW(14) SHROW(15) SHROW(16) SHROW(17) SHROW(18) SHROW(19)
    SHROW(20) SHROW(21) SHROW(22) SHROW(23) SHROW(24) SHROW(25) SHROW(26) SHROW(27) SHROW(28)
    SHROW(29) SHROW(30) SHROW(31) SHROW(32) SHROW(33) SHROW(34) SHROW(35) SHROW(36) SHROW(37)
    SHROW(38) SHROW(39) SHROW(40) SHROW(41) SHROW(42) SHROW(43) SHROW(44) SHROW(45) SHROW(46)
    SHROW(47) SHROW(48) SHROW(49) SHROW(50) SHROW(51) SHROW(52) SHROW(53) SHROW(54) SHROW(55)
    SHROW(56) SHROW(57) SHROW(58) SHROW(59) SHROW(60) SHROW(61) SHROW(62) SHROW(63)
    { 0, 0 }
};

static i64 op_not(i64 a)     { return ~a; }
static i64 op_neg(i64 a)     { return -a; }
static i64 op_lo8(i64 a)     { return a & 0xffLL; }
static i64 op_lo16(i64 a)    { return a & 0xffffLL; }
static i64 op_u8(i64 a)      { return (i64)(u8)a; }
static i64 op_u8sar8(i64 a)  { return (i64)(u8)(a >> 8); }
static i64 op_int(i64 a)     { return (i64)(int)a; }
static i64 op_lt0(i64 a)     { return a < 0; }
static i64 op_eq0(i64 a)     { return a == 0; }
static i64 op_bit16(i64 a)   { return (a >> 16) & 1; }
static i64 op_shl16m(i64 a)  { return (a & 0xffffLL) << 16; }
static i64 op_shl8m(i64 a)   { return (a & 0xffLL) << 8; }
static i64 op_rnd8(i64 a)    { return (a + 128) >> 8; }
static i64 op_carry(i64 a)   { i64 c = (a + 65536) >> 16; return a - c * 65536; }
static i64 op_carryc(i64 a)  { return (a + 65536) >> 16; }
static i64 op_selmask(i64 a) { return ~((a & 1) - 1); }
/* the same shifts through nacl.c's SAR16 workaround: these must ALWAYS be right */
static i64 op_sar16w(i64 a)  { return SAR16(a); }
static i64 op_carryw(i64 a)  { i64 c = SAR16(a + 65536); return a - c * 65536; }
static i64 op_carrycw(i64 a) { return SAR16(a + 65536); }

static i64 op_mul38(i64 a)    { return a * 38; }
static i64 op_mul37(i64 a)    { return a * 37; }
static i64 op_mul65536(i64 a) { return a * 65536; }
static i64 op_mul256(i64 a)   { return a * 256; }
static i64 op_mul16(i64 a)    { return 16 * a; }

static i64 bop_add(i64 a, i64 b) { return a + b; }
static i64 bop_sub(i64 a, i64 b) { return a - b; }
static i64 bop_mul(i64 a, i64 b) { return a * b; }
static i64 bop_lt(i64 a, i64 b)  { return a < b; }
static i64 bop_eq(i64 a, i64 b)  { return a == b; }
static i64 bop_and(i64 a, i64 b) { return a & b; }
static i64 bop_xor(i64 a, i64 b) { return a ^ b; }
static i64 bop_or(i64 a, i64 b)  { return a | b; }
static i64 bop_mulacc(i64 a, i64 b) { i64 t = 12345; t += a * b; t += a * a; return t; }
static i64 bop_sarv(i64 a, i64 b) { return a >> (int)b; }
static i64 bop_shlv(i64 a, i64 b) { return (a & 0xffffLL) << (int)b; }

static void detail_un(const char *name, unop_t f, const i64 *v, int n)
{
    char ha[20], hr[20];
    int i;
    for (i = 0; i < n; i++) {
        hex64(ha, v[i]);
        hex64(hr, f(v[i]));
        printf("       %s(%s) = %s\n", name, ha, hr);
    }
}

static void run_un(const char *name, unop_t f, const i64 *v, int n)
{
    char h[20], line[80];
    u32 acc = 2166136261UL;
    int i, ok;
    for (i = 0; i < n; i++) { hex64(h, f(v[i])); acc = fnv(acc, h); }
    sprintf(line, "un %s n=%d fnv=%08lx", name, n, (unsigned long)acc);
    tolerate = known_compiler_bug(name);
    ok = put_line(line);
    tolerate = 0;
    if (!gen_mode && (verbose || (!ok && !known_compiler_bug(name) && ndetail++ < 3)))
        detail_un(name, f, v, n);
}

static void detail_bin(const char *name, binop_t f, const i64 *va, int na, const i64 *vb, int nb)
{
    char ha[20], hb[20], hr[20];
    int i, j;
    for (i = 0; i < na; i++)
        for (j = 0; j < nb; j++) {
            hex64(ha, va[i]);
            hex64(hb, vb[j]);
            hex64(hr, f(va[i], vb[j]));
            printf("       %s(%s, %s) = %s\n", name, ha, hb, hr);
        }
}

static void run_bin(const char *name, binop_t f, const i64 *va, int na, const i64 *vb, int nb)
{
    char h[20], line[80];
    u32 acc = 2166136261UL;
    int i, j, ok;
    for (i = 0; i < na; i++)
        for (j = 0; j < nb; j++) { hex64(h, f(va[i], vb[j])); acc = fnv(acc, h); }
    sprintf(line, "bin %s n=%d fnv=%08lx", name, na * nb, (unsigned long)acc);
    ok = put_line(line);
    if (!gen_mode && (verbose || (!ok && ndetail++ < 3))) detail_bin(name, f, va, na, vb, nb);
}

#define UN_WIDE(f)  run_un(#f, op_##f, wide, NELEM(wide))
#define UN_MODER(f) run_un(#f, op_##f, moder, NELEM(moder))
#define BIN_MM(f)   run_bin(#f, bop_##f, moder, NELEM(moder), moder, NELEM(moder))

static void int64_tests(void)
{
    int k;
    for (k = 0; shift_ops[k].name; k++) run_un(shift_ops[k].name, shift_ops[k].f, wide, NELEM(wide));
    UN_WIDE(sar16w); UN_WIDE(carryw); UN_WIDE(carrycw);
    UN_WIDE(not); UN_WIDE(neg); UN_WIDE(lo8); UN_WIDE(lo16); UN_WIDE(u8); UN_WIDE(u8sar8);
    UN_WIDE(int); UN_WIDE(lt0); UN_WIDE(eq0); UN_WIDE(bit16); UN_WIDE(shl16m); UN_WIDE(shl8m);
    UN_WIDE(rnd8); UN_WIDE(carry); UN_WIDE(carryc); UN_WIDE(selmask);
    UN_MODER(mul38); UN_MODER(mul37); UN_MODER(mul65536); UN_MODER(mul256); UN_MODER(mul16);
    BIN_MM(add); BIN_MM(sub); BIN_MM(mul); BIN_MM(lt); BIN_MM(eq); BIN_MM(and); BIN_MM(xor);
    BIN_MM(or); BIN_MM(mulacc);
    run_bin("sarv", bop_sarv, wide, NELEM(wide), sar_counts, NELEM(sar_counts));
    run_bin("shlv", bop_shlv, wide, NELEM(wide), shl_counts, NELEM(shl_counts));
}

/* ----------------------- 2./3. nacl.c's own arithmetic ----------------------- */

static u32 lcg_state;
static u32 lcg(void)
{
    lcg_state = lcg_state * 1664525UL + 1013904223UL;
    return lcg_state;
}

static void rand_gf(gf g, int centered)     /* limbs 0..65535, or -32768..32767 like fsub output */
{
    int i;
    for (i = 0; i < 16; i++) {
        g[i] = (i64)((lcg() >> 8) & 0xffffUL);
        if (centered) g[i] -= 32768;
    }
}

static void rand_bytes(u8 *p, int n)
{
    int i;
    for (i = 0; i < n; i++) p[i] = (u8)(lcg() >> 16);
}

static void emit_bytes(const char *name, const u8 *p, int n)
{
    char line[220];
    int i, k = sprintf(line, "%s:", name);
    for (i = 0; i < n; i++) k += sprintf(line + k, "%02x", p[i]);
    put_line(line);
}

static void emit_gf(const char *name, const gf g)
{
    char line[400], h[20];
    int i, k = sprintf(line, "%s:", name);
    for (i = 0; i < 16; i++) {
        hex64(h, g[i]);
        k += sprintf(line + k, " %s", h);
    }
    put_line(line);
}

static void emit_packed(const char *name, const gf g)
{
    u8 y[32];
    pack25519(y, g);
    emit_bytes(name, y, 32);
}

static const i64 carin[3][16] = {
    { 0x12345678LL, -0x7654321LL, 0x1ffffLL, -1LL, 65536LL, -65536LL, 0LL, 0x10000000000LL,
      -0x10000000000LL, 0xfffffLL, -0xfffffLL, 12345LL, -1LL, 70000LL, 0x7fffffffLL, -0x7fffffffLL },
    { 65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL,
      65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL, 65535LL },
    { -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL,
      -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL, -65536LL }
};

/* RFC 7748 section 5.2, first test vector */
static const u8 rfc_scalar[32] = {
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
    0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 };
static const u8 rfc_point[32] = {
    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
    0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c };

static void nacl_tests(void)
{
    gf a, b, c, e, p[4], q[4];
    u8 x[32], y[32], z[64], w[64], msg[40];
    char nm[32];
    int i, k;

    lcg_state = 0x9e3779b9UL;

    memset(x, 0xff, 32); x[0] = 0xed; x[31] = 0x7f;              /* p     -> 0 */
    unpack25519(a, x); pack25519(y, a); emit_bytes("pack(p)", y, 32);
    x[0] = 0xee;                                                  /* p + 1 -> 1 */
    unpack25519(a, x); pack25519(y, a); emit_bytes("pack(p+1)", y, 32);
    x[0] = 0xec;                                                  /* p - 1 -> itself */
    unpack25519(a, x); pack25519(y, a); emit_bytes("pack(p-1)", y, 32);
    memset(x, 0xff, 32); x[31] = 0x7f;                            /* 2^255 - 1 -> 18 */
    unpack25519(a, x); pack25519(y, a); emit_bytes("pack(2^255-1)", y, 32);
    for (k = 0; k < 3; k++) {
        rand_bytes(x, 32); x[31] &= 0x7f;
        unpack25519(a, x); pack25519(y, a);
        sprintf(nm, "pack(unpack%d)", k); emit_bytes(nm, y, 32);
    }

    for (k = 0; k < 3; k++) {
        for (i = 0; i < 16; i++) a[i] = carin[k][i];
        car25519(a);
        sprintf(nm, "car%d", k); emit_gf(nm, a);
        sprintf(nm, "carp%d", k); emit_packed(nm, a);
    }

    rand_gf(a, 0); rand_gf(b, 0);
    set25519(c, a); set25519(e, b);
    sel25519(c, e, 0); emit_gf("sel0a", c); emit_gf("sel0b", e);
    sel25519(c, e, 1); emit_gf("sel1a", c); emit_gf("sel1b", e);

    for (k = 0; k < 6; k++) {
        rand_gf(a, k >= 3);
        rand_gf(b, k >= 3);
        fadd(c, a, b); sprintf(nm, "fadd%d", k); emit_gf(nm, c);
        fsub(c, a, b); sprintf(nm, "fsub%d", k); emit_gf(nm, c);
        fmul(c, a, b); sprintf(nm, "fmul%d", k); emit_gf(nm, c);
        sprintf(nm, "fmulp%d", k); emit_packed(nm, c);
        fsqr(e, a);    sprintf(nm, "fsqr%d", k); emit_gf(nm, e);
        fsub(e, a, b); fmul(c, e, b); sprintf(nm, "fmulsub%d", k); emit_gf(nm, c);
    }
    for (i = 0; i < 16; i++) a[i] = 0xffffLL;                    /* worst-case magnitude */
    fmul(c, a, a); emit_gf("fmul-max", c);
    for (i = 0; i < 10; i++) fsqr(a, a);
    emit_gf("fsqr-chain", a);

    for (k = 0; k < 3; k++) {
        rand_gf(a, 0);
        inv25519(c, a);   sprintf(nm, "inv%d", k); emit_packed(nm, c);
        fmul(e, a, c);    sprintf(nm, "a*inv%d", k); emit_packed(nm, e);    /* must be 1 */
        pow2523(c, a);    sprintf(nm, "pow2523-%d", k); emit_packed(nm, c);
    }

    x25519(y, rfc_scalar, rfc_point); emit_bytes("x25519-rfc7748", y, 32);
    x25519_base(y, rfc_scalar);       emit_bytes("x25519-base-rfc", y, 32);
    for (k = 0; k < 2; k++) {
        rand_bytes(x, 32); rand_bytes(z, 32);
        x25519(y, x, z);
        sprintf(nm, "x25519-rand%d", k); emit_bytes(nm, y, 32);
    }

    memset(x, 0, 32); x[0] = 1;
    ge_scalarbase(p, x); ge_pack(y, p); emit_bytes("base*1", y, 32);   /* 5866...66 */
    x[0] = 2;
    ge_scalarbase(p, x); ge_pack(y, p); emit_bytes("base*2", y, 32);
    rand_bytes(x, 32); x[31] &= 0x0f;
    ge_scalarbase(p, x); ge_pack(y, p); emit_bytes("base*rand", y, 32);
    rand_bytes(z, 32); z[31] &= 0x0f;
    ge_scalarbase(q, z);
    ge_add(p, q); ge_pack(y, p); emit_bytes("ge_add", y, 32);

    rand_bytes(z, 64);
    reduce64(z); emit_bytes("reduce64", z, 64);

    sha512((const u8 *)"abc", 3, w); emit_bytes("sha512-abc", w, 64);

    rand_bytes(x, 32);
    ed25519_keypair(y, z, x);
    emit_bytes("ed25519-pk", y, 32);
    rand_bytes(msg, 40);
    ed25519_sign(w, msg, 40, z);
    emit_bytes("ed25519-sig", w, 64);
    sprintf(nm, "ed25519-verify=%d", ed25519_verify(w, msg, 40, y));
    put_line(nm);
}

int main(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-g") == 0) gen_mode = 1;
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
    }
    if (gen_mode)
        printf("/* GENERATED by  build/test_prims -g  on a host where the full suite passes.\n"
               "   Regenerate only if core/nacl.c's internal representation changes. */\n"
               "static const char *const ref_lines[] = {\n");
    int64_tests();
    nacl_tests();
    if (gen_mode) {
        printf("  0\n};\n#define REF_COUNT %d\n", nlines);
        return 0;
    }
    printf("prims: %d passed, %d failed\n", nlines - nbad - nnote, nbad);
    if (nnote) printf("prims: %d check(s) hit a known compiler bug that nacl.c works around (NOTE above)\n", nnote);
    return nbad ? 1 : 0;
}
