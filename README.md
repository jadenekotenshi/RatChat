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
notices, and anything without a more specific home. Each window is laid out the conventional IRC-
client way: a read-only scrolling message log on top (with a member-list sidebar too, for channel
windows), and a single-line input field of its own pinned to the bottom -- typing a line there and
pressing Return sends it as a `PRIVMSG` to that window's target; lines starting with `/` are
commands.

Each channel window also carries a member list (from `NAMES`, kept in sync by `JOIN`/`PART`/`QUIT`/
`NICK`), so `QUIT`/`NICK` notices show up in every channel the person was actually in, not just the
status window. Messages are timestamped and each nick gets a consistent color (a small fixed
palette, picked by hashing the nick, so the same person reads the same color for the life of the
window); the local user's own messages are always bold instead, regardless of nick. `Tab` completes
an unambiguous prefix against the current channel's member list (`: ` after a completion at the
start of the field, matching the classic IRC-client convention for addressing someone; a plain
space elsewhere); `Up`/`Down` recall previously submitted lines in that window's own input field.
CTCP `VERSION`/`PING`/`TIME` requests get an automatic reply; other CTCP requests, and `ACTION`,
are still just noted.

**Commands**: `/join #channel [key]`, `/part [#channel] [reason]`, `/msg <target> <text>`,
`/me <action>`, `/nick <newnick>`, `/quit [reason]`, `/close` (leaves+closes a channel window, or
just closes a query window), `/raw <line>` (send anything as-is). Anything else starting with `/`
is passed through as a raw command line, matching most real IRC clients -- there are many commands
(`WHOIS`, `WHO`, `LIST`, `AWAY`, `KICK`, `INVITE`, ...) not worth hand-coding one at a time when the
server already knows what to do with the raw line. A leading `//` sends a literal message starting
with `/`.

**Not built yet**: saved server profiles, and any of the fancier IRCv3 capabilities (SASL, message
tags, etc.).

## What was verified, and what was not

**Verified on the development Mac**:
- `make test` -- `term/vt.c`'s own 259 checks (copied from StepTTY, unmodified, still passing:
  no RatChat-specific coupling in the terminal emulator itself), plus 94 checks for
  `core/irc_parse.c` (prefix/command/param parsing, trailing-param edge cases, CTCP, and every
  outgoing command formatter, including the CTCP-reply formatter).
- `make irc-smoke` -- drives a *real* `AppController`/`IRCConnection`/`IRCChannelSession` stack
  against a scripted fake IRC server (a real TCP listener on `127.0.0.1`, not a mock): a real
  non-blocking `connect()`, real `NICK`/`USER` registration, `/join` opening a channel window on
  the server's own `JOIN` confirmation (not optimistically), `NAMES` populating the member list
  (with a real server's own `@`/`+`-prefixed format, and confirming the prefix is stripped so it
  still matches a later `JOIN`/`PART`/`QUIT`/`NICK`), further `JOIN`/`PART` keeping that list in
  sync, a `QUIT` for a tracked member showing up in *that member's* channel windows (not just
  status), incoming `PRIVMSG`/CTCP `ACTION` display, an automatic reply to a CTCP `VERSION`
  request (and confirming it does *not* pop open a query window for the requester), typed replies
  reaching the real socket *and* echoing locally, Tab-completion and Up-arrow history recall driven
  through the same `-control:textView:doCommandBySelector:` call AppKit itself would make for a
  real Tab/Up keypress in the input field (not the higher-level "line already submitted" shortcut
  most other checks use), `/me`, `/nick`, and `/quit`/disconnect. 32 checks, all passing.
- `make check-objc`, `make lint`.

**Confirmed on real OPENSTEP 4.2 hardware** (2026-09-23): the app builds, launches via `open`, and
successfully connects to a real server (`irc.86box.net`), sending and receiving messages. Applied
proactively rather than left to be rediscovered a third time: the `__ICON` Mach-O segment
Workspace Manager requires just to launch an app bundle at all (both StepSSH and StepTTY hit this
before either had one) -- and it worked on the very first try here. Everything else pty/fork/exec-
specific that StepTTY had to work around on real hardware (`setsid`/`waitpid` not being linkable,
`ONLCR`/`CRMOD`, `tcgetattr`/`tcsetattr`, `$TERM`) doesn't apply here at all -- RatChat never forks
a child process, it only opens a raw TCP socket, using exactly the non-blocking connect/select/
recv/send pattern `SSHSession.m` already proved works on real i386 *and* m68k hardware, and it
carried over cleanly.

**Not yet confirmed on real hardware**: everything added after that first real-hardware round --
the member list (`NSTableView`, used without issue in StepSSH's own `SFTPBrowser` but not yet
exercised by RatChat there), per-nick colors and timestamps, CTCP auto-replies, and the dedicated
input-field layout (moved off the original "type directly into the message log" design after
real-hardware feedback that the interface felt too minimal). Two specific things worth checking
first if anything looks off:
- `NSCalendarDate` (timestamps, the CTCP `TIME` reply) is standard OpenStep API but, unlike
  `NSDate`/`NSTimer` (already relied on throughout this whole family of projects' poll loops), has
  not been exercised on real OPENSTEP hardware by any of these projects before.
- `-control:textView:doCommandBySelector:` (the `NSTextField` delegate hook Tab-completion and
  Up/Down history recall are both built on, letting the input field keep editing while intercepting
  those specific keys) is standard OpenStep "Text System" API predating Mac OS X, but likewise not
  yet exercised here. If it turns out to be missing, the graceful fallback is that Tab/Up/Down just
  stop doing their special thing and fall back to the field's own default handling -- typing and
  Return-to-submit (a plain target-action, unrelated to this hook) are unaffected either way.

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
  own close delegate). Unlike either of those, input lives in its own single-line `NSTextField`
  pinned to the bottom of the window, not typed directly into the scrolling log above it -- Tab-
  completion and Up/Down history recall are both driven through the field's `-control:textView:
  doCommandBySelector:` delegate hook rather than raw keystroke interception. Channel windows also
  own a member-list `NSTableView` sidebar (the same widget class StepSSH's `SFTPBrowser` already
  uses for its file list), which `AppController` keeps in sync from `NAMES`/`JOIN`/`PART`/`QUIT`/
  `NICK`.
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
