#include "test.h"
#include "irc_parse.h"

static void t_prefix(void)
{
    irc_message m;

    CHECK(irc_parse_line(":nick!user@host.example PRIVMSG #chan :hello there", &m) == 1);
    CHECK(m.has_prefix == 1);
    CHECK(strcmp(m.prefix.nick, "nick") == 0);
    CHECK(strcmp(m.prefix.user, "user") == 0);
    CHECK(strcmp(m.prefix.host, "host.example") == 0);
    CHECK(m.prefix.has_userhost == 1);
    CHECK(strcmp(m.command, "PRIVMSG") == 0);
    CHECK(m.nparams == 2);
    CHECK(strcmp(m.params[0], "#chan") == 0);
    CHECK(strcmp(m.params[1], "hello there") == 0);

    CHECK(irc_parse_line(":irc.example.net 001 mynick :Welcome", &m) == 1);
    CHECK(m.has_prefix == 1);
    CHECK(strcmp(m.prefix.nick, "irc.example.net") == 0);
    CHECK(m.prefix.has_userhost == 0);
    CHECK(strcmp(m.command, "001") == 0);

    CHECK(irc_parse_line(":nick@host NOTICE me :hi", &m) == 1);
    CHECK(strcmp(m.prefix.nick, "nick") == 0);
    CHECK(m.prefix.user[0] == '\0');
    CHECK(strcmp(m.prefix.host, "host") == 0);
    CHECK(m.prefix.has_userhost == 1);
}

static void t_no_prefix(void)
{
    irc_message m;

    CHECK(irc_parse_line("PING :abc123", &m) == 1);
    CHECK(m.has_prefix == 0);
    CHECK(strcmp(m.command, "PING") == 0);
    CHECK(m.nparams == 1);
    CHECK(strcmp(m.params[0], "abc123") == 0);
}

static void t_multi_params(void)
{
    irc_message m;

    CHECK(irc_parse_line(":srv 353 me = #chan :one two three", &m) == 1);
    CHECK(m.nparams == 4);
    CHECK(strcmp(m.params[0], "me") == 0);
    CHECK(strcmp(m.params[1], "=") == 0);
    CHECK(strcmp(m.params[2], "#chan") == 0);
    CHECK(strcmp(m.params[3], "one two three") == 0);
}

static void t_trailing_without_colon_needed(void)
{
    irc_message m;

    /* JOIN with no trailing param at all */
    CHECK(irc_parse_line(":nick!u@h JOIN #chan", &m) == 1);
    CHECK(m.nparams == 1);
    CHECK(strcmp(m.params[0], "#chan") == 0);
}

static void t_trailing_with_colon_but_no_spaces(void)
{
    irc_message m;

    /* A trailing param is allowed to be colon-introduced even without embedded spaces
     * (irc_fmt_join relies on exactly this for its optional key). */
    CHECK(irc_parse_line("JOIN :#chan", &m) == 1);
    CHECK(m.nparams == 1);
    CHECK(strcmp(m.params[0], "#chan") == 0);
}

static void t_empty_trailing(void)
{
    irc_message m;

    CHECK(irc_parse_line(":nick!u@h PART #chan :", &m) == 1);
    CHECK(m.nparams == 2);
    CHECK(strcmp(m.params[1], "") == 0);
}

static void t_malformed(void)
{
    irc_message m;

    CHECK(irc_parse_line("", &m) == 0);
    CHECK(irc_parse_line(":", &m) == 0);
    CHECK(irc_parse_line("   ", &m) == 0);
}

static void t_extra_whitespace_tolerance(void)
{
    irc_message m;

    CHECK(irc_parse_line(":n!u@h  PRIVMSG   #c  :hi", &m) == 1);
    CHECK(strcmp(m.command, "PRIVMSG") == 0);
    CHECK(strcmp(m.params[0], "#c") == 0);
    CHECK(strcmp(m.params[1], "hi") == 0);
}

static void t_channel_detection(void)
{
    CHECK(irc_is_channel("#general") == 1);
    CHECK(irc_is_channel("&local") == 1);
    CHECK(irc_is_channel("+moderated") == 1);
    CHECK(irc_is_channel("!abcde") == 1);
    CHECK(irc_is_channel("somenick") == 0);
}

static void t_ctcp(void)
{
    char buf[64];
    const char *verb, *body;

    strcpy(buf, "\001ACTION waves\001");
    CHECK(irc_is_ctcp(buf) == 1);
    irc_ctcp_strip(buf, &verb, &body);
    CHECK(strcmp(verb, "ACTION") == 0);
    CHECK(strcmp(body, "waves") == 0);

    CHECK(irc_is_ctcp("just text") == 0);
    CHECK(irc_is_ctcp("\001") == 0);        /* one byte: no closing marker distinct from opening */

    strcpy(buf, "\001VERSION\001");         /* verb with no body */
    irc_ctcp_strip(buf, &verb, &body);
    CHECK(strcmp(verb, "VERSION") == 0);
    CHECK(strcmp(body, "") == 0);
}

static void t_fmt_privmsg(void)
{
    char buf[IRC_MAX_LINE];
    int n = irc_fmt_privmsg(buf, sizeof(buf), "#chan", "hello world");
    CHECK(n > 0);
    CHECK(strcmp(buf, "PRIVMSG #chan :hello world\r\n") == 0);
    CHECK((int)strlen(buf) == n);
}

static void t_fmt_action(void)
{
    char buf[IRC_MAX_LINE];
    CHECK(irc_fmt_action(buf, sizeof(buf), "#chan", "waves") > 0);
    CHECK(strcmp(buf, "PRIVMSG #chan :\001ACTION waves\001\r\n") == 0);
}

static void t_fmt_join_part(void)
{
    char buf[IRC_MAX_LINE];

    CHECK(irc_fmt_join(buf, sizeof(buf), "#chan", NULL) > 0);
    CHECK(strcmp(buf, "JOIN #chan\r\n") == 0);

    CHECK(irc_fmt_join(buf, sizeof(buf), "#chan", "secret") > 0);
    CHECK(strcmp(buf, "JOIN #chan :secret\r\n") == 0);
    {
        /* and it must round-trip back through the parser correctly */
        irc_message m;
        buf[strlen(buf) - 2] = '\0';        /* strip the \r\n the parser doesn't expect */
        CHECK(irc_parse_line(buf, &m) == 1);
        CHECK(strcmp(m.params[0], "#chan") == 0);
        CHECK(strcmp(m.params[1], "secret") == 0);
    }

    CHECK(irc_fmt_part(buf, sizeof(buf), "#chan", NULL) > 0);
    CHECK(strcmp(buf, "PART #chan\r\n") == 0);

    CHECK(irc_fmt_part(buf, sizeof(buf), "#chan", "goodbye") > 0);
    CHECK(strcmp(buf, "PART #chan :goodbye\r\n") == 0);
}

static void t_fmt_nick_user_quit_pong(void)
{
    char buf[IRC_MAX_LINE];

    CHECK(irc_fmt_nick(buf, sizeof(buf), "ratty") > 0);
    CHECK(strcmp(buf, "NICK ratty\r\n") == 0);

    CHECK(irc_fmt_user(buf, sizeof(buf), "ratty", "Rat Chat User") > 0);
    CHECK(strcmp(buf, "USER ratty 0 * :Rat Chat User\r\n") == 0);

    CHECK(irc_fmt_quit(buf, sizeof(buf), NULL) > 0);
    CHECK(strcmp(buf, "QUIT\r\n") == 0);

    CHECK(irc_fmt_quit(buf, sizeof(buf), "bye") > 0);
    CHECK(strcmp(buf, "QUIT :bye\r\n") == 0);

    CHECK(irc_fmt_pong(buf, sizeof(buf), "abc123") > 0);
    CHECK(strcmp(buf, "PONG :abc123\r\n") == 0);
}

static void t_fmt_too_small(void)
{
    char buf[8];
    CHECK(irc_fmt_privmsg(buf, sizeof(buf), "#averylongchannelname", "a message that will not fit") == -1);
}

static void t_fmt_raw(void)
{
    char buf[IRC_MAX_LINE];
    CHECK(irc_fmt_raw(buf, sizeof(buf), "WHOIS someone") > 0);
    CHECK(strcmp(buf, "WHOIS someone\r\n") == 0);
}

int main(void)
{
    t_prefix();
    t_no_prefix();
    t_multi_params();
    t_trailing_without_colon_needed();
    t_trailing_with_colon_but_no_spaces();
    t_empty_trailing();
    t_malformed();
    t_extra_whitespace_tolerance();
    t_channel_detection();
    t_ctcp();
    t_fmt_privmsg();
    t_fmt_action();
    t_fmt_join_part();
    t_fmt_nick_user_quit_pong();
    t_fmt_too_small();
    t_fmt_raw();
    TEST_DONE("irc_parse");
}
