#include "dcc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Case-insensitive prefix match, C89-safe (no strncasecmp guaranteed present). */
static int starts_with_ci(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    size_t i;
    for (i = 0; i < n; i++) {
        char a = s[i], b = prefix[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

int dcc_parse_send(const char *body, dcc_send_offer *out)
{
    const char *p = body;

    memset(out, 0, sizeof(*out));
    if (!starts_with_ci(p, "SEND")) return 0;
    p += 4;
    while (*p == ' ') p++;

    if (*p == '"') {
        const char *start = ++p;
        while (*p && *p != '"') p++;
        if (*p != '"') return 0;
        {
            size_t n = (size_t)(p - start);
            if (n >= sizeof(out->filename)) n = sizeof(out->filename) - 1;
            memcpy(out->filename, start, n);
            out->filename[n] = '\0';
        }
        p++;
    } else {
        const char *start = p;
        while (*p && *p != ' ') p++;
        {
            size_t n = (size_t)(p - start);
            if (n >= sizeof(out->filename)) n = sizeof(out->filename) - 1;
            memcpy(out->filename, start, n);
            out->filename[n] = '\0';
        }
    }
    if (out->filename[0] == '\0') return 0;
    while (*p == ' ') p++;

    out->ip = strtoul(p, (char **)&p, 10);
    while (*p == ' ') p++;
    out->port = (int)strtol(p, (char **)&p, 10);
    while (*p == ' ') p++;
    out->size = strtol(p, (char **)&p, 10);

    return out->port > 0 && out->size >= 0;
}

int dcc_fmt_send_offer(char *out, size_t outsz, const char *filename, unsigned long ip, int port, long size)
{
    int hasSpace = strchr(filename, ' ') != NULL;
    int n;
    if (hasSpace)
        n = sprintf(out, "DCC SEND \"%s\" %lu %d %ld", filename, ip, port, size);
    else
        n = sprintf(out, "DCC SEND %s %lu %d %ld", filename, ip, port, size);
    if (n < 0 || (size_t)n >= outsz) return -1;
    return n;
}

unsigned long dcc_ip_from_string(const char *dotted_quad)
{
    unsigned long a, b, c, d;
    if (sscanf(dotted_quad, "%lu.%lu.%lu.%lu", &a, &b, &c, &d) != 4) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

void dcc_ip_to_string(unsigned long ip, char *out)
{
    sprintf(out, "%lu.%lu.%lu.%lu",
            (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}
