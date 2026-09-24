#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "../core/ssh_types.h"
#include "../core/tls_pins.h"
#include "test.h"

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

int main(void)
{
    const char *path = "build/tls_pins_test.tmp";
    u8 der[64], other_der[64];
    struct stat st;
    int i;

    for (i = 0; i < 64; i++) der[i] = (u8)(i * 3 + 7);
    for (i = 0; i < 64; i++) other_der[i] = (u8)(i * 5 + 11);

    remove(path);
    CHECK(tlspin_check(path, "irc.example.org", 6697, der, sizeof(der)) == TLSPIN_UNKNOWN);   /* no file */
    CHECK(tlspin_add(path, "irc.example.org", 6697, der, sizeof(der)) == 0);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0077) == 0);                                  /* 0600 */

    CHECK(tlspin_check(path, "irc.example.org", 6697, der, sizeof(der)) == TLSPIN_MATCH);
    CHECK(tlspin_check(path, "IRC.Example.ORG", 6697, der, sizeof(der)) == TLSPIN_MATCH);      /* case-insensitive */
    CHECK(tlspin_check(path, "irc.example.org", 6697, other_der, sizeof(other_der)) == TLSPIN_CHANGED);
    CHECK(tlspin_check(path, "irc.example.org", 6698, der, sizeof(der)) == TLSPIN_UNKNOWN);    /* port is part of identity */
    CHECK(tlspin_check(path, "other.example.org", 6697, der, sizeof(der)) == TLSPIN_UNKNOWN);

    /* the user accepts a changed certificate: a fresh add makes future checks against the new
     * cert match again, without needing to edit out the now-stale entry (matches knownhosts.c's
     * own precedent). The old entry is still on file too, so it still matches on its own --
     * append-only means accepted certificates stay valid, they're never later invalidated by a
     * newer pin. */
    CHECK(tlspin_add(path, "irc.example.org", 6697, other_der, sizeof(other_der)) == 0);
    CHECK(tlspin_check(path, "irc.example.org", 6697, other_der, sizeof(other_der)) == TLSPIN_MATCH);
    CHECK(tlspin_check(path, "irc.example.org", 6697, der, sizeof(der)) == TLSPIN_MATCH);

    /* a second, unrelated host:port pin coexists cleanly */
    CHECK(tlspin_add(path, "other.example.org", 6697, der, sizeof(der)) == 0);
    CHECK(tlspin_check(path, "other.example.org", 6697, der, sizeof(der)) == TLSPIN_MATCH);
    CHECK(tlspin_check(path, "irc.example.org", 6697, other_der, sizeof(other_der)) == TLSPIN_MATCH);

    /* junk must not crash */
    write_file(path, "\x01\x02 garbage\n||| |\nhost\nhost 6697\nhost 6697 tooshort\nhost notaport abcd\n");
    for (i = 0; i < 4; i++) CHECK(tlspin_check(path, "host", 6697, der, sizeof(der)) == TLSPIN_UNKNOWN);

    remove(path);
    TEST_DONE("tls_pins");
}
