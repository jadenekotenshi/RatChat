/*
 * ssh_types.h -- fixed-width types for a C89 / gcc 2.7.2 world.
 *
 * OPENSTEP 4.2 has no <stdint.h>.  int is 32 bits and long long is 64 bits on
 * every OPENSTEP target (i386, SPARC, PA-RISC, m68k), so these are safe.
 * The code never depends on byte order: all loads/stores go through the
 * LOAD/STORE macros below.
 */
#ifndef SSH_TYPES_H
#define SSH_TYPES_H

#include <stddef.h>

typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned long long u64;

typedef char ssh_assert_u8 [(sizeof(u8)  == 1) ? 1 : -1];
typedef char ssh_assert_u32[(sizeof(u32) == 4) ? 1 : -1];
typedef char ssh_assert_u64[(sizeof(u64) == 8) ? 1 : -1];

#define ROR32(x, n) ((((x) >> (n)) | ((x) << (32 - (n)))) & 0xffffffffUL)
#define ROL32(x, n) ((((x) << (n)) | ((x) >> (32 - (n)))) & 0xffffffffUL)
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define LOAD32_BE(p) \
    (((u32)(p)[0] << 24) | ((u32)(p)[1] << 16) | ((u32)(p)[2] << 8) | (u32)(p)[3])
#define LOAD32_LE(p) \
    (((u32)(p)[3] << 24) | ((u32)(p)[2] << 16) | ((u32)(p)[1] << 8) | (u32)(p)[0])
#define STORE32_BE(p, v) do { \
    (p)[0] = (u8)((v) >> 24); (p)[1] = (u8)((v) >> 16); \
    (p)[2] = (u8)((v) >> 8);  (p)[3] = (u8)(v); } while (0)
#define STORE32_LE(p, v) do { \
    (p)[3] = (u8)((v) >> 24); (p)[2] = (u8)((v) >> 16); \
    (p)[1] = (u8)((v) >> 8);  (p)[0] = (u8)(v); } while (0)

#define LOAD64_BE(p) \
    (((u64)LOAD32_BE(p) << 32) | (u64)LOAD32_BE((p) + 4))
#define STORE64_BE(p, v) do { \
    u32 hi_ = (u32)((v) >> 32), lo_ = (u32)(v); \
    STORE32_BE((p), hi_); STORE32_BE((p) + 4, lo_); } while (0)

/* Zero memory in a way the optimizer is unlikely to elide. */
void ssh_wipe(void *p, size_t n);
/* Constant-time compare; returns 0 if equal. */
int ssh_ct_memcmp(const void *a, const void *b, size_t n);

#endif
