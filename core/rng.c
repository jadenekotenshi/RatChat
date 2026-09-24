#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "rng.h"
#include "sha2.h"
#include "oscompat.h"

extern char **environ;

static u8  pool[64];
static int pool_init;
static int credited;
static u32 counter;

static void pool_ensure(void)
{
    if (!pool_init) { memset(pool, 0, sizeof(pool)); pool_init = 1; }
}

void ssh_rng_add(const void *data, size_t len, int bits)
{
    sha512_ctx c;
    u8 tag = 'A';
    pool_ensure();
    sha512_init(&c);
    sha512_update(&c, &tag, 1);
    sha512_update(&c, pool, sizeof(pool));
    sha512_update(&c, data, len);
    sha512_final(&c, pool);
    if (bits > 0) {
        credited += bits;
        if (credited > 512) credited = 512;
    }
}

void ssh_rng_add_timing(int bits)
{
    struct timeval tv;
    u8 b[16];
    u32 a, u, pid;
    gettimeofday(&tv, NULL);
    a = (u32)tv.tv_sec; u = (u32)tv.tv_usec; pid = (u32)getpid();
    STORE32_LE(b, a); STORE32_LE(b + 4, u); STORE32_LE(b + 8, (u32)clock());
    STORE32_LE(b + 12, pid ^ counter);
    ssh_rng_add(b, sizeof(b), bits);
}

static void add_junk(void)
{
    char **e;
    struct stat st;
    static const char *paths[] = { "/", "/tmp", "/etc/passwd", "/dev/console", NULL };
    int i;

    ssh_rng_add_timing(0);
    for (e = environ; e && *e; e++) ssh_rng_add(*e, strlen(*e), 0);
    for (i = 0; paths[i]; i++)
        if (stat(paths[i], &st) == 0) ssh_rng_add(&st, sizeof(st), 0);
    ssh_rng_add_timing(0);
}

int ssh_rng_seed_system(void)
{
    static const char *devs[] = { "/dev/urandom", "/dev/random", NULL };
    u8 buf[64];
    int i, got = 0;
    add_junk();
    for (i = 0; devs[i] && !got; i++) {
        FILE *f = fopen(devs[i], "rb");
        if (!f) continue;
        if (fread(buf, 1, sizeof(buf), f) == sizeof(buf)) got = 1;
        fclose(f);
    }
    if (!got) return 0;
    ssh_rng_add(buf, sizeof(buf), 256);
    ssh_wipe(buf, sizeof(buf));
    return 256;
}

int ssh_rng_save_seed(const char *path)
{
    u8 seed[64];
    FILE *f;
    if (ssh_rng_bytes(seed, sizeof(seed)) != 0) return -1;
    f = fopen(path, "wb");
    if (!f) { ssh_wipe(seed, sizeof(seed)); return -1; }
    chmod(path, 0600);
    fwrite(seed, 1, sizeof(seed), f);
    fclose(f);
    ssh_wipe(seed, sizeof(seed));
    return 0;
}

int ssh_rng_load_seed(const char *path)
{
    u8 seed[64];
    struct stat st;
    FILE *f;
    size_t n;

    add_junk();
    if (stat(path, &st) != 0 || (st.st_mode & 077) != 0) return 0;   /* absent or too open */
    f = fopen(path, "rb");
    if (!f) return 0;
    n = fread(seed, 1, sizeof(seed), f);
    fclose(f);
    if (n != sizeof(seed)) { ssh_wipe(seed, sizeof(seed)); return 0; }
    ssh_rng_add(seed, sizeof(seed), 256);
    ssh_wipe(seed, sizeof(seed));
    /* The old seed must never be reused: replace it before doing anything else. */
    ssh_rng_save_seed(path);
    return 256;
}

int ssh_rng_credited(void) { return credited; }
int ssh_rng_ready(void)    { return credited >= SSH_RNG_MIN_BITS; }

int ssh_rng_bytes(void *out, size_t len)
{
    u8 *o = (u8 *)out;
    u8 blk[64], ctrb[4], tag;
    sha512_ctx c;
    size_t n;

    if (!ssh_rng_ready()) return -1;
    while (len) {
        tag = 'G';
        STORE32_BE(ctrb, counter);
        counter++;
        sha512_init(&c);
        sha512_update(&c, &tag, 1);
        sha512_update(&c, pool, sizeof(pool));
        sha512_update(&c, ctrb, 4);
        sha512_final(&c, blk);
        n = len < 32 ? len : 32;           /* use half the block, keep half hidden */
        memcpy(o, blk, n);
        o += n; len -= n;
    }
    /* ratchet the pool forward so earlier output can't be recomputed later */
    tag = 'R';
    sha512_init(&c);
    sha512_update(&c, &tag, 1);
    sha512_update(&c, pool, sizeof(pool));
    sha512_final(&c, pool);
    ssh_wipe(blk, sizeof(blk));
    return 0;
}
