/*
 * dcc.h -- DCC (Direct Client-to-Client) SEND request parsing/formatting and the classic
 * decimal-encoded IPv4 address DCC uses (e.g. "3232235521" for 192.168.1.1 -- a plain 32-bit
 * unsigned integer, not a dotted quad, for historical mIRC-compatibility reasons every client
 * still follows). Pure C89: only string/integer conversion, no sockets, no I/O -- the actual
 * connection (listening for SEND, connecting for RECEIVE, streaming the file) is DCCTransfer's
 * job (app/DCCTransfer.m), same split as irc_parse.c/IRCConnection.m.
 *
 * A DCC offer arrives as a CTCP message (see irc_parse.h's irc_is_ctcp/irc_ctcp_strip) whose verb
 * is "DCC" and whose body is "SEND <filename> <ip> <port> <size>" -- a filename containing spaces
 * is double-quoted by the sender, so this parses that too.
 */
#ifndef DCC_H
#define DCC_H
#include <stddef.h>

#define DCC_MAX_FILENAME 256

typedef struct {
    char          filename[DCC_MAX_FILENAME];
    unsigned long ip;             /* classic DCC decimal-encoded IPv4, not a dotted quad */
    int           port;
    long          size;
} dcc_send_offer;

/* `body` is the CTCP message's body with "DCC " already stripped by the caller (irc_ctcp_strip
 * gives the verb "DCC" and this as everything after it) -- so `body` starts with "SEND ...".
 * Returns 1 on success, 0 if it isn't a recognized "SEND ..." request. */
int dcc_parse_send(const char *body, dcc_send_offer *out);

/* Writes "DCC SEND <filename> <ip> <port> <size>" into out (capacity outsz) -- the CTCP body,
 * not yet wrapped in the 0x01 markers or a PRIVMSG (irc_fmt_privmsg handles that, same as any
 * other CTCP message). Quotes filename if it contains a space. Returns the length written, or -1
 * if it wouldn't fit. */
int dcc_fmt_send_offer(char *out, size_t outsz, const char *filename, unsigned long ip, int port, long size);

/* The classic DCC address encoding: a plain 32-bit unsigned integer whose big-endian byte layout
 * is the IPv4 address's own octets, printed/parsed in decimal rather than as a dotted quad. */
unsigned long dcc_ip_from_string(const char *dotted_quad);
void          dcc_ip_to_string(unsigned long ip, char *out);      /* out: at least 16 bytes */

#endif
