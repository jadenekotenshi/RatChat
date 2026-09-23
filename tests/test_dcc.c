#include "test.h"
#include "dcc.h"

static void t_parse_plain(void)
{
    dcc_send_offer o;
    CHECK(dcc_parse_send("SEND readme.txt 3232235777 1234 5678", &o) == 1);
    CHECK(strcmp(o.filename, "readme.txt") == 0);
    CHECK(o.ip == 3232235777UL);
    CHECK(o.port == 1234);
    CHECK(o.size == 5678);
}

static void t_parse_quoted_filename(void)
{
    dcc_send_offer o;
    CHECK(dcc_parse_send("SEND \"my cool file.txt\" 3232235777 1234 5678", &o) == 1);
    CHECK(strcmp(o.filename, "my cool file.txt") == 0);
    CHECK(o.ip == 3232235777UL);
    CHECK(o.port == 1234);
    CHECK(o.size == 5678);
}

static void t_parse_case_insensitive_verb(void)
{
    dcc_send_offer o;
    CHECK(dcc_parse_send("send readme.txt 1 1 1", &o) == 1);
}

static void t_parse_rejects_other_verbs(void)
{
    dcc_send_offer o;
    CHECK(dcc_parse_send("CHAT chat 3232235777 1234", &o) == 0);
    CHECK(dcc_parse_send("RESUME readme.txt 1234 100", &o) == 0);
    CHECK(dcc_parse_send("", &o) == 0);
}

static void t_parse_malformed(void)
{
    dcc_send_offer o;
    CHECK(dcc_parse_send("SEND", &o) == 0);                        /* no filename at all */
    CHECK(dcc_parse_send("SEND \"unterminated", &o) == 0);
    CHECK(dcc_parse_send("SEND readme.txt 3232235777 0 5678", &o) == 0);   /* port 0: invalid */
}

static void t_fmt_send_offer(void)
{
    char buf[512];
    int n = dcc_fmt_send_offer(buf, sizeof(buf), "readme.txt", 3232235777UL, 1234, 5678);
    CHECK(n > 0);
    CHECK(strcmp(buf, "DCC SEND readme.txt 3232235777 1234 5678") == 0);
}

static void t_fmt_send_offer_quotes_spaces(void)
{
    char buf[512];
    int n = dcc_fmt_send_offer(buf, sizeof(buf), "my cool file.txt", 3232235777UL, 1234, 5678);
    CHECK(n > 0);
    CHECK(strcmp(buf, "DCC SEND \"my cool file.txt\" 3232235777 1234 5678") == 0);
}

static void t_fmt_and_parse_round_trip(void)
{
    char buf[512];
    dcc_send_offer o;
    dcc_fmt_send_offer(buf, sizeof(buf), "a file with spaces.bin", 3232235777UL, 6789, 999999);
    CHECK(dcc_parse_send(buf + 4, &o) == 1);      /* +4: dcc_parse_send expects "DCC " already stripped */
    CHECK(strcmp(o.filename, "a file with spaces.bin") == 0);
    CHECK(o.ip == 3232235777UL);
    CHECK(o.port == 6789);
    CHECK(o.size == 999999);
}

static void t_ip_conversion(void)
{
    char buf[16];
    CHECK(dcc_ip_from_string("192.168.1.1") == 3232235777UL);
    CHECK(dcc_ip_from_string("127.0.0.1") == 2130706433UL);
    dcc_ip_to_string(3232235777UL, buf);
    CHECK(strcmp(buf, "192.168.1.1") == 0);
    dcc_ip_to_string(2130706433UL, buf);
    CHECK(strcmp(buf, "127.0.0.1") == 0);
}

int main(void)
{
    t_parse_plain();
    t_parse_quoted_filename();
    t_parse_case_insensitive_verb();
    t_parse_rejects_other_verbs();
    t_parse_malformed();
    t_fmt_send_offer();
    t_fmt_send_offer_quotes_spaces();
    t_fmt_and_parse_round_trip();
    t_ip_conversion();
    TEST_DONE("dcc");
}
