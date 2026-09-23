#include "irc_parse.h"
#include <string.h>

/* Bounds-checked copy: copies up to (cap-1) bytes from [src, src+n), always NUL-terminates. */
static void copyn(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void copyz(char *dst, size_t cap, const char *src)
{
    copyn(dst, cap, src, strlen(src));
}

static void parse_prefix(irc_prefix *p, const char *s, size_t n)
{
    const char *bang = (const char *)memchr(s, '!', n);
    const char *at;
    size_t nickLen;

    memset(p, 0, sizeof(*p));
    if (bang) {
        at = (const char *)memchr(bang + 1, '@', (size_t)((s + n) - (bang + 1)));
        nickLen = (size_t)(bang - s);
        copyn(p->nick, sizeof(p->nick), s, nickLen);
        if (at) {
            copyn(p->user, sizeof(p->user), bang + 1, (size_t)(at - (bang + 1)));
            copyn(p->host, sizeof(p->host), at + 1, (size_t)((s + n) - (at + 1)));
            p->has_userhost = 1;
        } else {
            copyn(p->user, sizeof(p->user), bang + 1, (size_t)((s + n) - (bang + 1)));
            p->has_userhost = 1;
        }
        return;
    }
    at = (const char *)memchr(s, '@', n);
    if (at) {
        copyn(p->nick, sizeof(p->nick), s, (size_t)(at - s));
        copyn(p->host, sizeof(p->host), at + 1, (size_t)((s + n) - (at + 1)));
        p->has_userhost = 1;
        return;
    }
    copyn(p->nick, sizeof(p->nick), s, n);            /* just a servername */
}

int irc_parse_line(const char *line, irc_message *out)
{
    const char *p = line;

    memset(out, 0, sizeof(*out));
    while (*p == ' ') p++;

    if (*p == ':') {
        const char *start = ++p;
        while (*p && *p != ' ') p++;
        if (p == start) return 0;
        parse_prefix(&out->prefix, start, (size_t)(p - start));
        out->has_prefix = 1;
        while (*p == ' ') p++;
    }

    {
        const char *start = p;
        while (*p && *p != ' ') p++;
        if (p == start) return 0;
        copyn(out->command, sizeof(out->command), start, (size_t)(p - start));
    }
    while (*p == ' ') p++;

    while (*p && out->nparams < IRC_MAX_PARAMS) {
        if (*p == ':') {
            copyz(out->params[out->nparams], IRC_MAX_LINE, p + 1);
            out->nparams++;
            break;
        }
        {
            const char *start = p;
            while (*p && *p != ' ') p++;
            copyn(out->params[out->nparams], IRC_MAX_LINE, start, (size_t)(p - start));
            out->nparams++;
        }
        while (*p == ' ') p++;
    }
    return 1;
}

int irc_is_channel(const char *target)
{
    return target[0] == '#' || target[0] == '&' || target[0] == '+' || target[0] == '!';
}

int irc_is_ctcp(const char *text)
{
    size_t n = strlen(text);
    return n >= 2 && text[0] == '\001' && text[n - 1] == '\001';
}

void irc_ctcp_strip(char *text, const char **verb, const char **body)
{
    char *end = text + strlen(text) - 1;               /* the closing 0x01 */
    char *p = text + 1;                                 /* past the opening 0x01 */
    *end = '\0';
    *verb = p;
    while (*p && *p != ' ') p++;
    if (*p == ' ') { *p = '\0'; p++; }
    *body = p;
}

/* Builds "<command><SP>...<SP>:<text>\r\n" (text may be omitted). Returns the length written
 * (without the NUL), or -1 if it would not fit in outsz. No snprintf (not guaranteed present on
 * OPENSTEP 4.2), so every piece's length is checked by hand before copying. */
static int build(char *out, size_t outsz, const char *cmd, const char *mid, const char *text)
{
    size_t need = strlen(cmd) + 2;                        /* "CMD\r\n" at minimum */
    size_t midLen = mid ? strlen(mid) : 0;
    size_t textLen = text ? strlen(text) : 0;
    char *w = out;

    if (mid) need += 1 + midLen;                          /* " mid" */
    if (text) need += 2 + textLen;                        /* " :text" */
    if (need + 1 > outsz) return -1;                       /* +1 for the NUL */

    memcpy(w, cmd, strlen(cmd)); w += strlen(cmd);
    if (mid) { *w++ = ' '; memcpy(w, mid, midLen); w += midLen; }
    if (text) { *w++ = ' '; *w++ = ':'; memcpy(w, text, textLen); w += textLen; }
    *w++ = '\r'; *w++ = '\n'; *w = '\0';
    return (int)(w - out);
}

int irc_fmt_privmsg(char *out, size_t outsz, const char *target, const char *text)
{
    return build(out, outsz, "PRIVMSG", target, text);
}

int irc_fmt_notice(char *out, size_t outsz, const char *target, const char *text)
{
    return build(out, outsz, "NOTICE", target, text);
}

int irc_fmt_action(char *out, size_t outsz, const char *target, const char *text)
{
    char wrapped[IRC_MAX_LINE];
    size_t n = strlen(text);
    if (n + 10 >= sizeof(wrapped)) n = sizeof(wrapped) - 10;   /* "\001ACTION \001" overhead */
    wrapped[0] = '\001';
    memcpy(wrapped + 1, "ACTION ", 7);
    memcpy(wrapped + 8, text, n);
    wrapped[8 + n] = '\001';
    wrapped[9 + n] = '\0';
    return build(out, outsz, "PRIVMSG", target, wrapped);
}

int irc_fmt_ctcp_reply(char *out, size_t outsz, const char *target, const char *verb, const char *arg)
{
    char wrapped[IRC_MAX_LINE];
    size_t verbLen = strlen(verb);
    size_t argLen = arg ? strlen(arg) : 0;
    size_t n = 1 + verbLen + (arg ? 1 + argLen : 0);     /* "\001VERB[ arg]" */
    if (n + 1 >= sizeof(wrapped)) n = sizeof(wrapped) - 2;
    wrapped[0] = '\001';
    memcpy(wrapped + 1, verb, verbLen);
    if (arg) { wrapped[1 + verbLen] = ' '; memcpy(wrapped + 2 + verbLen, arg, argLen); }
    wrapped[n] = '\001';
    wrapped[n + 1] = '\0';
    return build(out, outsz, "NOTICE", target, wrapped);
}

int irc_fmt_join(char *out, size_t outsz, const char *channel, const char *key)
{
    return build(out, outsz, "JOIN", channel, key);
}

int irc_fmt_part(char *out, size_t outsz, const char *channel, const char *reason)
{
    return build(out, outsz, "PART", channel, reason);
}

int irc_fmt_nick(char *out, size_t outsz, const char *nick)
{
    return build(out, outsz, "NICK", nick, NULL);
}

int irc_fmt_user(char *out, size_t outsz, const char *user, const char *realname)
{
    char mid[3 * IRC_MAX_NICK];
    size_t userLen = strlen(user);
    if (userLen >= IRC_MAX_NICK) userLen = IRC_MAX_NICK - 1;
    memcpy(mid, user, userLen);
    memcpy(mid + userLen, " 0 *", 4);
    mid[userLen + 4] = '\0';
    return build(out, outsz, "USER", mid, realname);
}

int irc_fmt_quit(char *out, size_t outsz, const char *reason)
{
    return build(out, outsz, "QUIT", NULL, reason);
}

int irc_fmt_pong(char *out, size_t outsz, const char *token)
{
    return build(out, outsz, "PONG", NULL, token);
}

int irc_fmt_raw(char *out, size_t outsz, const char *line)
{
    size_t n = strlen(line);
    if (n + 3 > outsz) return -1;
    memcpy(out, line, n);
    out[n] = '\r'; out[n + 1] = '\n'; out[n + 2] = '\0';
    return (int)(n + 2);
}
