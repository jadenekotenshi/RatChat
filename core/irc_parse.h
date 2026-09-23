/*
 * irc_parse.h -- IRC (RFC 1459/2812) line parsing and outgoing-command formatting.
 *
 * Pure C89, no I/O: parse a raw line already stripped of its trailing CR/LF into a structured
 * irc_message, or format an outgoing command into a line ready to send (with CR/LF appended).
 * Fixed-size buffers throughout, matching RFC 2812's own 512-byte (including CRLF) line limit.
 */
#ifndef IRC_PARSE_H
#define IRC_PARSE_H
#include <stddef.h>

#define IRC_MAX_LINE   512
#define IRC_MAX_PARAMS 15
#define IRC_MAX_NICK   64
#define IRC_MAX_HOST   128

typedef struct {
    char nick[IRC_MAX_NICK];
    char user[IRC_MAX_NICK];
    char host[IRC_MAX_HOST];
    int  has_userhost;         /* 0: prefix was just a server name (nick holds it, user/host empty) */
} irc_prefix;

typedef struct {
    int         has_prefix;
    irc_prefix  prefix;
    char        command[16];               /* e.g. "PRIVMSG", "001", "JOIN" */
    char        params[IRC_MAX_PARAMS][IRC_MAX_LINE];
    int         nparams;                   /* the trailing (":"-introduced) param, if any, is last */
} irc_message;

/* Parses one line (no trailing CR/LF). Returns 1 on success, 0 if the line has no command at all
 * (empty, or prefix with nothing after it) -- otherwise tolerant, per RFC guidance to servers'
 * own tolerance of minor deviations, since real-world IRC servers are not perfectly RFC-strict. */
int irc_parse_line(const char *line, irc_message *out);

/* True if `target` (a PRIVMSG/JOIN/etc. parameter) names a channel rather than a nick, per the
 * standard prefix characters (#&+!). */
int irc_is_channel(const char *target);

/* CTCP: true if `text` is a single CTCP-quoted message (wrapped in 0x01), and if so, *verb_len is
 * set to the length of its leading verb word (e.g. "ACTION", "VERSION") and *body points just past
 * the verb (and its following space, if any) to the rest of the message, NUL-terminated in place
 * by irc_ctcp_strip (which also strips the trailing 0x01). Neither points outside `text`. */
int irc_is_ctcp(const char *text);
void irc_ctcp_strip(char *text, const char **verb, const char **body);

/* Outgoing command formatting: writes "<command> ...\r\n" into out (capacity outsz), returns the
 * length written (excluding the NUL), or -1 if it wouldn't fit. `text` may be NULL for commands
 * with no trailing parameter. */
int irc_fmt_privmsg(char *out, size_t outsz, const char *target, const char *text);
int irc_fmt_notice(char *out, size_t outsz, const char *target, const char *text);
int irc_fmt_action(char *out, size_t outsz, const char *target, const char *text);   /* CTCP ACTION */
int irc_fmt_ctcp_reply(char *out, size_t outsz, const char *target, const char *verb, const char *arg);
int irc_fmt_join(char *out, size_t outsz, const char *channel, const char *key);     /* key may be NULL */
int irc_fmt_part(char *out, size_t outsz, const char *channel, const char *reason);  /* reason may be NULL */
int irc_fmt_nick(char *out, size_t outsz, const char *nick);
int irc_fmt_user(char *out, size_t outsz, const char *user, const char *realname);
int irc_fmt_quit(char *out, size_t outsz, const char *reason);                       /* reason may be NULL */
int irc_fmt_pong(char *out, size_t outsz, const char *token);
int irc_fmt_raw(char *out, size_t outsz, const char *line);      /* line as-is, plus "\r\n" */

#endif
