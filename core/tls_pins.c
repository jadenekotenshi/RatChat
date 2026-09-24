#include "tls_pins.h"
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "oscompat.h"

static void hex32(const u8 in[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 0xf]; }
    out[64] = '\0';
}

static int ci_eq(const char *a, size_t alen, const char *b, size_t blen)
{
    size_t i;
    if (alen != blen) return 0;
    for (i = 0; i < alen; i++) {
        int ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return 1;
}

int tlspin_check(const char *path, const char *host, int port, const u8 *der, size_t der_len)
{
    FILE *f = fopen(path, "r");
    char line[600];
    char want[65];
    u8 fp[32];
    int result = TLSPIN_UNKNOWN;
    size_t hlen = strlen(host);

    if (!f) return TLSPIN_UNKNOWN;
    sha256(der, der_len, fp);
    hex32(fp, want);

    while (fgets(line, sizeof(line), f)) {
        char *p = line, *h, *portstr, *fp_str;
        size_t hn;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;
        h = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        hn = (size_t)(p - h);
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        portstr = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        fp_str = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        *p = '\0';

        if (!ci_eq(h, hn, host, hlen)) continue;
        if (atoi(portstr) != port) continue;
        if (strlen(fp_str) != 64) continue;

        result = TLSPIN_CHANGED;
        if (strcmp(fp_str, want) == 0) { result = TLSPIN_MATCH; break; }
    }
    fclose(f);
    return result;
}

int tlspin_add(const char *path, const char *host, int port, const u8 *der, size_t der_len)
{
    FILE *f;
    char hex[65];
    u8 fp[32];

    sha256(der, der_len, fp);
    hex32(fp, hex);

    f = fopen(path, "a");
    if (!f) return -1;
    chmod(path, 0600);
    fprintf(f, "%s %d %s\n", host, port, hex);
    fclose(f);
    return 0;
}
