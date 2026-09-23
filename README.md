# RatChat for OPENSTEP 4.2

A native IRC client for OPENSTEP 4.2, in C89/Objective-C. Sibling project to
[StepSSH](https://github.com/jadenekotenshi/StepSSH) (an SSH-2 client) and
[StepTTY](https://github.com/jadenekotenshi/StepTTY) (a local terminal emulator) for the same
platform: reuses StepSSH's/StepTTY's `TerminalView` (as a scrolling message-log pane, one per
channel/query/status window) and mirrors StepSSH's `SSHSession` raw-socket handling (the same
non-blocking connect/select/recv/send pattern, the same 20&nbsp;ms `NSTimer` poll loop, already
confirmed on real i386 and m68k hardware there) for its own `IRCConnection`.

## What it does

Connects to one IRC server (see "Server > Connect..."). Each joined channel and each private
message conversation gets its own window; a "Server" status window shows the MOTD, connection
notices, and anything without a more specific home. Typing a line and pressing Return sends it as
a `PRIVMSG` to that window's target; lines starting with `/` are commands.

Since a raw socket doesn't echo anything back the way a pty's line discipline does, each window
does its own minimal local line editing (printable characters, backspace, Enter) -- see
`IRCChannelSession.m`'s `-terminalView:sendBytes:length:` for why, and for the one subtlety that
comes with it: an incoming message arriving mid-keystroke is spliced in around the user's
not-yet-submitted line rather than corrupting it (erase, print, re-echo).

**Commands**: `/join #channel [key]`, `/part [#channel] [reason]`, `/msg <target> <text>`,
`/me <action>`, `/nick <newnick>`, `/quit [reason]`, `/close` (leaves+closes a channel window, or
just closes a query window), `/raw <line>` (send anything as-is). Anything else starting with `/`
is passed through as a raw command line, matching most real IRC clients -- there are many commands
(`WHOIS`, `WHO`, `LIST`, `AWAY`, `KICK`, `INVITE`, ...) not worth hand-coding one at a time when the
server already knows what to do with the raw line. A leading `//` sends a literal message starting
with `/`.

**Not built yet**: a NAMES/user list per channel (so `QUIT` notices go to the status window only,
not to every channel the user was seen in -- there's no membership tracking to route them with),
CTCP auto-replies (VERSION/PING/TIME requests are noted in the status window but not answered),
saved server profiles, and any of the fancier IRCv3 capabilities (SASL, message tags, etc.).

## What was verified, and what was not

**Verified on the development Mac**:
- `make test` -- `term/vt.c`'s own 259 checks (copied from StepTTY, unmodified, still passing:
  no RatChat-specific coupling in the terminal emulator itself), plus 88 new checks for
  `core/irc_parse.c` (prefix/command/param parsing, trailing-param edge cases, CTCP, and every
  outgoing command formatter).
- `make irc-smoke` -- drives a *real* `AppController`/`IRCConnection`/`IRCChannelSession` stack
  against a scripted fake IRC server (a real TCP listener on `127.0.0.1`, not a mock): a real
  non-blocking `connect()`, real `NICK`/`USER` registration, `/join` opening a channel window on
  the server's own `JOIN` confirmation (not optimistically), an incoming `PRIVMSG` and CTCP
  `ACTION` both displaying correctly, typed replies reaching the real socket *and* echoing locally
  (since the server never echoes a client's own message back), `/me`, `/nick` updating the
  tracked nick only once the server confirms it, and `/quit`/disconnect. 19 checks, all passing.
- `make check-objc`, `make lint`.

**Confirmed on real OPENSTEP 4.2 hardware**: nothing yet -- this is a brand new project. Applied
proactively rather than left to be rediscovered a third time: the `__ICON` Mach-O segment
Workspace Manager requires just to launch an app bundle at all (both StepSSH and StepTTY hit this
before either had one). Everything else pty/fork/exec-specific that StepTTY had to work around on
real hardware (`setsid`/`waitpid` not being linkable, `ONLCR`/`CRMOD`, `tcgetattr`/`tcsetattr`,
`$TERM`) doesn't apply here at all -- RatChat never forks a child process, it only opens a raw TCP
socket, using exactly the non-blocking connect/select/recv/send pattern `SSHSession.m` already
proved works on real i386 *and* m68k hardware. That pattern should carry over the same way, but
"should" is not "has" -- report back exactly what happens on the first real build/run.

## Building

```sh
make test        # FIRST: the terminal emulator core + IRC protocol parsing, on the dev host
make irc-smoke    # a real socket/connection/window session, end to end, against a fake server
make lint check-objc     # style/portability checks
```

```sh
make -f Makefile.openstep test         # FIRST: the C core on the real compiler
make -f Makefile.openstep              # builds RatChat.app
make -f Makefile.openstep install      # into /LocalApps
make -f Makefile.openstep pkg          # RatChat.pkg for Installer.app
make -f Makefile.openstep dist         # RatChat.pkg, gzipped as RatChat-<VERSION>-<letter>.tar.gz
make -f Makefile.openstep fat          # RatChat.app as an i386+m68k+sparc fat binary
make -f Makefile.openstep install-fat  # fat app into /LocalApps
make -f Makefile.openstep pkg-fat      # RatChat.pkg with the fat build
make -f Makefile.openstep dist-fat     # fat RatChat.pkg, gzipped as RatChat-<VERSION>-NIS.tar.gz
```

See `Makefile.openstep`'s own comments for exactly what each one assumes and why, carried over
directly from what StepSSH's own packaging saga established (the real `Installer.app/package`
tool, the plain-text `.info` format, `LongFileNames NO`, `chgrp nogroup`, the `N`/`I`/`S`/`NIS`
`dist` naming) rather than re-derived from nothing.

## Architecture notes

- `term/vt.c`/`term/nsenc.c`, `app/TerminalView.m`/`.h` -- copied from StepTTY (itself copied from
  StepSSH) essentially unmodified: a pure C89 VT100/xterm-subset terminal emulator core used here
  purely as a scrolling display widget (no pty, no escape-sequence-driven remote control -- IRC
  message text is just written into it as plain lines).
- `app/UIHelpers.m`/`.h` -- copied from StepTTY: the small control factories, the `SSTrace`
  startup-diagnostics helper, and `ui_string_from_utf8`/`ui_utf8_cstring` (IRC message bytes are
  usually, but not guaranteedly, UTF-8 -- these decode/encode safely either way).
- `core/irc_parse.c`/`.h` -- new. Pure C89, no I/O: parses one raw IRC line into prefix/command/
  params, and formats every outgoing command this client sends. Deliberately does *not* reuse
  StepSSH's `core/wire.c` (`sbuf`/`sreader`/mpint/base64) -- that machinery exists for SSH's binary
  wire format, and IRC is a much simpler newline-terminated text protocol that doesn't need it.
- `app/IRCConnection.m`/`.h` -- new. Owns the one raw TCP socket, mirroring `SSHSession.m`'s
  non-blocking connect/select/recv/send pattern and 20&nbsp;ms poll loop closely on purpose (already
  proven reliable on real OPENSTEP hardware there), plus its own inbound line-buffering (IRC has no
  protocol engine to lean on for this the way SSH does) and outbound backpressure queue.
- `app/IRCChannelSession.m`/`.h` -- new. One window per channel, query, or the server status;
  mirrors `PTYSession`/`SSHSession` closely (owns its window and `TerminalView`, is the window's
  own close delegate), with local line editing standing in for what a pty's line discipline gave
  StepTTY for free.
- `app/AppController.m`/`.h` -- new. Owns the app's one `IRCConnection` and every open
  `IRCChannelSession`; is the connection's delegate (the central router deciding which window a
  parsed message belongs to, and formatting it for display) and each session's owner (dispatching
  submitted lines as either a slash command or a plain `PRIVMSG`).
- `app/ConnectController.m`/`.h` -- new. A small server/port/nick/username/real-name panel,
  shaped like StepSSH's own connect panel but trimmed to what an unauthenticated IRC connection
  actually needs.

## Startup diagnostics

Workspace throws a launched application's stderr away. `touch ~/.RatChat.trace` before launching
(from Workspace or `open`) to get the same startup narration `main.m`'s `NSLog` calls print, in a
file instead.
