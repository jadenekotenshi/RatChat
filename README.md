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
just closes a query window), `/raw <line>` (send anything as-is), `/dcc send <nick> <path>` (see
below). Anything else starting with `/` is passed through as a raw command line, matching most
real IRC clients -- there are many commands (`WHOIS`, `WHO`, `LIST`, `AWAY`, `KICK`, `INVITE`, ...)
not worth hand-coding one at a time when the server already knows what to do with the raw line. A
leading `//` sends a literal message starting with `/`.

**DCC file transfer** (`core/dcc.c`, `app/DCCTransfer.m`): `/dcc send <nick> <path>` offers a file
-- RatChat opens a listening socket and sends the classic CTCP `DCC SEND` offer (filename, its own
address as seen by the existing server connection, the port, the file size) as a `PRIVMSG` to that
nick; the transfer itself is a completely separate direct connection from the peer, not routed
through the IRC server at all. Receiving one prompts Accept/Decline, then (if accepted) where to
save it; declining sends back a `DCC REJECT` notice. Progress is shown in that nick's own query
window (auto-opened if not already open), roughly every 25% rather than on every chunk. No NAT
traversal or manual address override -- the address offered is whatever the existing IRC
connection's own local endpoint reports, which works on a LAN or a direct connection but not
through most home routers' NAT without port forwarding. Also skips the old per-chunk 4-byte-ack
convention some DCC implementations use for flow control, since TCP already provides that.

**TLS** (`core/tls.c` and friends, `app/IRCConnection.m`'s `useTLS` path): a "Use TLS" switch in
the connect panel (toggling the port field's own default between `6667`/`6697`) gets a real,
from-scratch TLS 1.2 client -- OPENSTEP 4.2 has nothing to build on, so this is genuinely a
from-scratch implementation on roughly the scale of StepSSH's own SSH crypto, built on top of
crypto primitives vendored in from there (SHA-2, HMAC, bignum, ECDSA/ECDH, RSA verification,
AES, ChaCha20-Poly1305, all already hardware-confirmed via StepSSH's own shipped product).
Deliberately narrow scope, matching real networks' actual requirements rather than the whole of
what TLS 1.2 can do: ECDHE key exchange only (X25519 preferred, P-256 fallback), AEAD cipher
suites only -- `ECDHE-{RSA,ECDSA}-AES128-GCM-SHA256` and the two ChaCha20-Poly1305 equivalents --
no CBC suites, no renegotiation, no session resumption, no client certificates, and no TLS 1.3.
Trust is TOFU (trust-on-first-use) pinning of the whole leaf certificate's DER, by SHA-256, in a
new `~/.ratchat/tls_pins` -- mirrors StepSSH's own `~/.ssh/known_hosts` model for SSH host keys
exactly (same underlying question: "is this the same server identity I trusted before," not "is
this transitively trusted by a CA"), including the same unknown/changed distinction and trust
dialog shape. No CA chain validation, no revocation checking, no hostname-vs-SubjectAltName
matching at all. A TLS handshake also needs real randomness for its ephemeral keys; on a machine
with no usable `/dev/urandom` (real OPENSTEP 4.2, confirmed) the very first TLS connection of a
session shows a small "Seeding random number generator" panel and asks you to wiggle the mouse
over it -- mirrors StepSSH's own entropy-seeding panel exactly, including saving the seed to
`~/.ratchat/rng_seed` afterward so later launches don't need it again. Plaintext IRC never touches
this at all.

**Not built yet**: DCC CHAT (direct chat bypassing the server -- only DCC SEND, file transfer, is
built), saved server profiles, and any of the fancier IRCv3 capabilities (SASL, message tags,
etc.).

## What was verified, and what was not

**Verified on the development Mac**:
- `make test` -- `term/vt.c`'s own 259 checks (copied from StepTTY, unmodified, still passing:
  no RatChat-specific coupling in the terminal emulator itself), 94 checks for `core/irc_parse.c`
  (prefix/command/param parsing, trailing-param edge cases, CTCP, and every outgoing command
  formatter), 30 checks for `core/dcc.c` (DCC SEND request parsing including quoted filenames,
  the classic decimal IP encoding both ways, and every formatter, all round-tripped), and just
  over 9900 more across every TLS-related module (plus 301 for the compiler's own 64-bit
  arithmetic, `tests/test_prims.c`): the vendored crypto primitives against
  StepSSH's own already-hardware-confirmed results; `core/der.c`/`core/x509.c` against three real
  openssl-generated certificates (RSA-2048, EC-P256, EC-P384), every value cross-checked
  independently via openssl's own tools, plus full truncation/corruption sweeps; `core/tls_prf.c`
  against a real captured local TLS 1.2 handshake's actual derived keys; `core/tls_aead_gcm.c`/
  `tls_aead_chacha.c` against RFC 8439's own published vector and four real captured TLS records,
  independently decrypted by linked OpenSSL before being trusted as vectors; `core/tls.c` itself
  against hand-built record/handshake-message reassembly at every possible split point (including
  a real network's own `CertificateRequest` -- see below), and `core/tls_pins.c` against the same
  unknown/match/changed/append-only model `core/knownhosts.c` already established for SSH host
  keys.
- `make tls-smoke` -- drives a real `tls_session`, as a real TCP client, through a complete TLS
  1.2 handshake against a real local `openssl s_server` (spawned by the test itself), for both
  `ECDHE-RSA-AES128-GCM-SHA256` and `ECDHE-RSA-CHACHA20-POLY1305`, plus a third round
  (`openssl s_server -verify 1`) reproducing real IRC networks' habit of sending
  `CertificateRequest` unconditionally to offer optional TLS client-certificate login; confirms the
  independently derived `master_secret` matches OpenSSL's own `-keylogfile` output bit-for-bit each
  time, and that the `CertificateRequest` round actually exercised the new code path. 18 checks.
- `make irc-tls-smoke` -- the same idea at the app layer: a real `AppController`/`IRCConnection`
  stack, TLS turned on, against a real local `openssl s_server`, with a pre-seeded TOFU pin so
  the (genuinely modal) trust dialog never needs a click. Confirms `NICK`/`USER` actually reach
  the real server decrypted correctly, and that a scripted server response decrypts correctly and
  completes registration. 4 checks.
- `make entropy-gate-smoke` -- confirms `AppController` actually gates a TLS connection attempt on
  a real, un-seeded `core/rng.c` pool (showing the entropy-seeding panel and holding the request)
  rather than either failing fast or connecting anyway with too little randomness, and that a
  plaintext connection is never gated on it at all. Has to run first in its own fresh process,
  since the RNG pool is global static state with no reset -- see the test file's own header. 14
  checks.
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
  most other checks use), `/me`, `/nick`, and `/quit`/disconnect. 32 checks, all passing --
  unaffected by TLS's own arrival, since `IRCConnection.m`'s plaintext path and its TLS path
  share the same line-splitting and backpressure code underneath.
- `make dcc-smoke` -- drives two real `DCCTransfer` instances (one sending, one receiving) against
  each other over a real `127.0.0.1` connection: a real listen/accept and a real non-blocking
  connect, a 200KB file (well over one 8KB read/write chunk, so several send()/recv() rounds are
  actually exercised) copied byte-for-byte correctly end to end, progress notifications firing on
  both sides, and a connection to a real-but-refusing port failing cleanly rather than hanging.
  15 checks, all passing.
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
carried over cleanly. Also confirmed, in a later round the same day: `make fat` (i386+m68k+sparc)
works, and the dedicated input-field layout (including Tab-completion/Up-Down history, so
`-control:textView:doCommandBySelector:` does exist and work on real OPENSTEP 4.2) does the right
thing.

**Confirmed on real OPENSTEP 4.2 hardware** (2026-09-24): TLS connects successfully end to end --
after fixing the five bugs described below, a real TLS connection (via an intermediate VM) both
built and completed a real handshake, closing out the last major unconfirmed piece of the TLS
effort. A separate real-hardware-only quirk was also found and fixed this round: after Return
submits a line in a channel/query window's input field, the field lost focus and needed an extra
click before the next message could be typed -- classic (pre-Mac-OS-X) AppKit does not restore
focus to a field on its own after Return the way modern Cocoa does. Fixed in
`-[IRCChannelSession inputSubmitted:]` by reclaiming first responder explicitly; flagged `[V]`
since it is not reproducible host-side at all (a real synthetic Return keypress here never loses
focus in the first place, confirmed by directly testing it), so only the user's own next round of
real-hardware testing can confirm the fix actually holds.

**Not yet confirmed on real hardware**: the member list (`NSTableView`, used without issue in
StepSSH's own `SFTPBrowser` but not yet exercised by RatChat there), per-nick colors and
timestamps, CTCP auto-replies, and DCC file transfer. `NSCalendarDate`
(timestamps, the CTCP `TIME` reply, and now the TLS trust dialog's not-yet-valid/expired
warning) is standard OpenStep API but, unlike `NSDate`/`NSTimer` (already relied on throughout
this whole family of projects' poll loops), has not been exercised on real OPENSTEP hardware by
any of these projects before -- worth checking first if anything looks off there specifically.
DCC's own socket code is the same already-proven non-blocking connect/select/recv/send pattern
as `IRCConnection`, plus a plain `listen()`/`accept()` for the sending side (also standard BSD
sockets, no reason to expect trouble, but genuinely new to this codebase); `NSSavePanel` (used
to choose where to save an incoming file) is confirmed working in StepSSH.

TLS specifically: every crypto primitive, every protocol-parsing/framing piece, and the full
handshake state machine were tested extremely thoroughly on the host first (see above) --
including full round trips against real, independent OpenSSL, both at the raw engine level
(`make tls-smoke`) and through the actual app wiring (`make irc-tls-smoke`) -- before any of it ran
on gcc 2.7.2 or real i386/m68k hardware. It now has, and connects successfully (see "Confirmed on
real OPENSTEP 4.2 hardware" above). Still genuinely open, since a successful connection alone
doesn't settle either question: whether the pure-C89 crypto code's performance is acceptable on
real period hardware for a handshake against a real public server (none of StepSSH's own crypto
primitives were performance-profiled on real hardware either, just confirmed correct -- worth a
deliberate look now that a full round trip works at all), and whether every real public IRC
network's actual TLS configuration, not just the one tested, lands inside this client's
deliberately narrow scope.

Real-hardware bugs found and fixed while getting there (each one only surfaced compiling/running
on the real thing -- `check-objc`/`make test` on the dev Mac couldn't have caught any of them):
`ConnectController.m`'s "Use TLS" switch compared its state against `NSOnState`, which real
OPENSTEP 4.2 headers never declared (modern AppKit still ships it as a deprecated-but-present
alias); `DCCTransfer.m` used a raw `socklen_t` at one call site instead of the file's own
OPENSTEP-gated `sock_len_t` typedef (POSIX.1g, 1998 -- newer than OPENSTEP 4.2's own headers);
RatChat's app layer never seeded `core/rng.c` at all, so a TLS connection's `tls_start()`
correctly failed fast with "not enough entropy" the moment real hardware (with no `/dev/urandom`)
actually needed real randomness -- fixed by porting StepSSH's own entropy-seeding panel over (see
"What it does" above and `make entropy-gate-smoke`); and the new entropy panel's own label text
was split across two lines relying on implicit adjacent string-literal concatenation between an
`@"..."` and a plain `"..."`, which real gcc 2.7.2 does not reliably accept (`tools/
check_string_concat.py`, now in `make lint`, catches this class going forward).

A fifth bug was a real protocol gap, not a portability issue -- reproducible on the dev Mac too,
once tested against a real network rather than a local `openssl s_server`: real IRC networks
(confirmed against `irc.libera.chat`) send `CertificateRequest` unconditionally during the
handshake, to offer optional TLS client-certificate ("CertFP") login, whether or not the client
intends to use it. `core/tls.c`'s handshake dispatcher had no case for that message type at all,
so a real connection failed with "unexpected handshake message type" the moment a real network
(rather than this project's own single-cert local test server) was involved. Fixed per RFC 5246
SS7.4.6: the client still must not skip this step, but replies with an empty Certificate message
(`core/tls.c`'s new `handle_certificate_request`/`got_cert_request`) rather than actually
presenting one -- client certificates remain an explicit non-goal. Confirmed two ways: a third
`make tls-smoke` round against a real local `openssl s_server -verify 1` (18 checks total now),
and a one-off host-side connection straight to `irc.libera.chat:6697` using RatChat's own
unmodified `core/tls.c`, which completed the full handshake (`ECDHE-RSA-CHACHA20-POLY1305`) and a
real IRC registration, MOTD included, end to end.

All five bugs above were found and fixed in the course of getting from "builds on the host" to
"connects on real OPENSTEP 4.2 hardware, against a real public network" -- which, as of
2026-09-24, TLS now does.

## Building

```sh
make test          # FIRST: the terminal emulator core + IRC/DCC/TLS protocol parsing+crypto, on the dev host
make irc-smoke      # a real socket/connection/window session, end to end, against a fake server
make dcc-smoke      # a real file transfer, end to end, between two DCCTransfer instances
make tls-smoke      # a real TLS 1.2 handshake, end to end, against a real local openssl s_server
make irc-tls-smoke  # the same, but through the actual app-layer TLS wiring
make entropy-gate-smoke  # confirms TLS (and only TLS) gates on the RNG pool being seeded
make lint check-objc     # style/portability checks
make bench-bulk         # per-primitive cost of the TLS data path (host figures are only a smoke test)
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
make -f Makefile.openstep bench-bulk   # per-primitive cost of the TLS data path, on the machine you run it on
```

`fat`/`install-fat`/`pkg-fat`/`dist-fat` all go through one shared `fat-build` target, which `clean`s
first (so a fat build never links against thin object files left over from a plain build). It
compiles the three architectures as three separate passes and `lipo -create`s the results, rather
than as one multi-`-arch` `cc` invocation, so each architecture gets its own tuning, ported from
StepSSH where each was benched on real hardware: `-m486` for i386, `-O2 -fomit-frame-pointer
-m68040` (`M68KOPT`) for m68k, and `-O2 -mv8` (`SPARCOPT`) for SPARC -- except `core/chacha.c`, which
alone builds at `-O -mv8` there (`SPARCCHACHAOPT`; Poly1305 lives in the same file). `-mv8` uses the
hardware integer multiply instead of gcc 2.7.2's default V7 code's library calls; it is safe because
OPENSTEP only ran on the sun4m SPARCstations, every one of them V8. Each is a set of
single-architecture gcc switches the other backends reject, and NeXT's `cc` cannot scope a flag to
one `-arch` inside a single invocation. A plain (thin) build picks the same flags automatically when
`arch(1)` reports i386, m68k or sparc.

See `Makefile.openstep`'s own comments for exactly what each one assumes and why, carried over
directly from what StepSSH's own packaging saga established (the real `Installer.app/package`
tool, the plain-text `.info` format, `LongFileNames NO`, `chgrp nogroup`, the `N`/`I`/`S`/`NIS`
`dist` naming) rather than re-derived from nothing.

## Bulk throughput

RatChat vendors StepSSH's crypto, and StepSSH's throughput pass (2026-09-29) has been ported across
unchanged in substance: `core/aes.c`/`aes_tab.h` (32-bit-word AES with one 1 KB table each way),
`core/chacha.c` (quarter rounds on locals, XOR fused into the block and done as aligned 32-bit words
on little-endian CPUs), `core/sha1.c`/`sha2.c`/`md5.c` (unrolled rounds, one-`memset` padding,
`ssh_wipe` as a `memset` through a volatile pointer), and RatChat's own `core/tls_aead_gcm.c`, whose
GHASH went from bit-serial to 4-bit tables (Shoup's method, with the tables derived from the spec's
multiply-by-x so there is no separate constant table to get wrong). On StepSSH, as reported by the
person who ran them on real hardware, throughput on the i386 was significantly higher, on the 68040
AES-256-CTR improved by approximately 450% and chacha20-poly1305 by more than 3x. `core/nacl.c` already carried the fix for
gcc 2.7.2's m68k miscompile of a 64-bit arithmetic right shift by exactly 16 (RatChat 0.2.1).

`make bench-bulk` (`make -f Makefile.openstep bench-bulk` on OPENSTEP) times ChaCha20, Poly1305,
whole TLS records through `tls_chacha_seal`/`open` and `tls_gcm_seal`/`open` (64 B, 1400 B and 16 KB),
the hashes, HMAC-SHA256 and X25519 -- so a change can be compared before and after on the same
machine. The host's figures are below; a modern compiler already optimizes some of the old code, so
they understate the gain on the real machines (see the hardware note at the end of this section). On
the host a 16 KB AES-128-GCM record seals in 72 us instead of 875 us (about 12x), SHA-1 runs at 743
instead of 451 MB/s, a 64-byte HMAC-SHA256 takes 0.8 us instead of 1.2, `ssh_wipe` of 16 KB 0.1 us
instead of 4.2, and ChaCha20-Poly1305 records are unchanged at about 23 us for 16 KB.

**Verified on the development Mac**: all 15 test binaries pass (10640 checks) plainly and under
ASan+UBSan (`make SAN=1 test`); the GCM rewrite is checked against an independent bit-serial GHASH
across two key sizes, 16 payload lengths and 6 AAD lengths (a deliberately corrupted table entry fails
197 of them); the ChaCha and AES changes are checked for every buffer alignment and chunking, and
Poly1305 against 44 edge-case vectors from an independent Python big-integer implementation;
`make tls-smoke` and `make irc-tls-smoke` still complete real TLS 1.2 handshakes and record exchange
against a real `openssl s_server` with both `ECDHE-RSA-AES128-GCM-SHA256` and
`ECDHE-RSA-CHACHA20-POLY1305`. The per-architecture build flags and the three-pass fat build were
checked by dry run with a faked `arch(1)`.

**Confirmed on real OPENSTEP 4.2 hardware** (2026-09-30, as reported by the person who ran it): on the
i386 and on SPARC, `bench-bulk` gives results similar to StepSSH's for the same primitives, and the app
works just as well as it did before the port. The test suite was run too and passed (the report did not
say per machine). No figures were recorded here.

**m68k (68040)** (2026-09-30, as reported by the person who ran it): the slice launches, makes a TLS
connection, and the whole test suite passes on it. That is the first time RatChat's TLS has run on the
68040, and it means the 0.2.1 fix for gcc 2.7.2's 64-bit `>> 16` miscompile (which made every X25519 key
exchange compute a wrong shared secret there) works in RatChat itself, not only in StepSSH -- the client
offers X25519 first, though the report did not say which curve or cipher suite the server picked. No
`bench-bulk` figures from the 68040 were reported.

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
  protocol engine to lean on for this the way SSH does) and outbound backpressure queue. When
  `useTLS` is set, `core/tls.c`'s engine sits between the raw socket and that same line-buffering/
  backpressure code -- `recv()`/`send()` themselves are completely unchanged, only what feeds them
  differs. The `TLS_EV_CERT` trust dialog reuses `SSHSession.m`'s own `-handleHostKey:` pattern
  exactly (a synchronous `NSRunAlertPanel`, backed by a TOFU pin store).
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
  submitted lines as either a slash command or a plain `PRIVMSG`). Also creates `~/.ratchat`
  (mode&nbsp;0700) at launch to hold `tls_pins`, the TOFU pin store `core/tls_pins.c` reads and
  writes. Best-effort seeds `core/rng.c` (vendored from StepSSH in Phase 0 of the TLS effort, but
  originally never wired up at the app layer at all -- a real bug, found on real hardware) at
  launch from `/dev/urandom` and a saved `~/.ratchat/rng_seed`; if a TLS connection is requested
  before the pool is credited enough, `-showEntropyPanel` (a straight port of StepSSH's own
  `EntropyMeter`/seeding-panel class) stashes the request and shows a "wiggle the mouse" panel,
  resuming the connection from `-entropyReady` once the pool is ready. Plaintext connections never
  touch any of this.
- `app/ConnectController.m`/`.h` -- new. A small server/port/nick/username/real-name panel,
  shaped like StepSSH's own connect panel but trimmed to what an unauthenticated IRC connection
  actually needs, plus a "Use TLS" switch that flips the port field's default between 6667 and
  6697.
- `core/tls.c`/`.h`+`tls_priv.h` -- new. A sans-I/O TLS&nbsp;1.2 client handshake/record engine,
  shaped identically to `ssh.h`/`ssh_priv.h` on purpose (`tls_new`/`free`/`start`/`input`/`output`/
  `output_done`/`next_event`/`write`/`is_closed`, the same event-queue pattern) -- it never touches
  a socket itself, `IRCConnection` owns all of the actual `recv()`/`send()`. ECDHE-only, AEAD-only:
  `TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256` and the ChaCha20-Poly1305 equivalents, X25519
  preferred over P-256. No CBC, no renegotiation, no session resumption, no TLS&nbsp;1.3. Handles
  two independent framing layers (5-byte record headers, and 4-byte handshake-message headers
  inside the decrypted record stream), each reassembled independently of how the caller's TCP reads
  happen to chop the bytes up.
- `core/tls_wire.c`/`.h` -- new. Length-prefixed vector helpers for TLS's own wire format, built on
  top of the untouched vendored `wire.c`'s `sbuf`/`sreader` rather than editing `wire.c` itself
  (keeps it byte-diffable against StepSSH's original). `core/tls_prf.c`/`.h` -- new. RFC&nbsp;5246
  §5's `P_hash`/PRF (fixed to SHA-256 for every suite this client offers), a pure composition on top
  of vendored `hmac.c`.
- `core/tls_aead_gcm.c`/`.h`, `core/tls_aead_chacha.c`/`.h` -- new. Two independent AEAD wrappers:
  GCM's own GHASH/counter-mode framing on top of vendored `aes.c`'s block primitive (TLS's GCM
  nonce is the 4-byte fixed IV concatenated with, not XOR'd with, an 8-byte explicit per-record
  nonce -- distinct from ChaCha20-Poly1305's implicit-nonce-via-XOR scheme), and the RFC&nbsp;8439
  IETF ChaCha20-Poly1305 construction on top of vendored `chacha.c`'s raw primitives (a single
  32-byte key, distinct from `chacha.c`'s own `chachapoly_*` OpenSSH split-key scheme, which stays
  unused here).
- `core/der.c`/`.h` -- new. A small DER/ASN.1 reader (nested SEQUENCEs, short/long-form lengths,
  BIT STRING, OID comparison, UTCTime/GeneralizedTime, a DER `SEQUENCE{INTEGER r, INTEGER s}`
  decoder for ECDSA signatures), modeled on `ssh_key.c`'s own file-local DER helpers but built out
  further since X.509 needs more structure than an SSH private-key file does.
- `core/x509.c`/`.h` -- new. Parses exactly as much of one leaf certificate as the TOFU trust model
  above needs: validity dates, subject CN (display only), and the SubjectPublicKeyInfo (RSA or EC)
  used to verify the handshake's ServerKeyExchange signature -- no chain walking, no issuer
  signature verification, no revocation checking.
- `core/tls_pins.c`/`.h` -- new. TOFU certificate pinning, mirroring `core/knownhosts.c`'s own
  shape exactly (`kh_check`/`add` &rarr; `tlspin_check`/`add`, `KH_UNKNOWN`/`MATCH`/`CHANGED`
  &rarr; `TLSPIN_*`) but pinning the whole leaf certificate's DER SHA-256 per host:port rather than
  just a public key. Append-only by design: an old accepted certificate stays a valid match
  forever, even after a newer one is pinned for the same host.
- `core/dcc.c`/`.h` -- new. Pure C89, no I/O: parses/formats the CTCP `DCC SEND` request (including
  quoted filenames) and the classic decimal-encoded IPv4 address DCC uses instead of a dotted
  quad. `app/DCCTransfer.m`/`.h` -- new. One direct peer-to-peer file transfer, entirely separate
  from the server connection it was negotiated over -- mirrors `IRCConnection`'s own non-blocking
  connect/select/recv/send pattern and poll loop, plus a plain `listen()`/`accept()` for the
  offering (sending) side, and its own accept/connect timeout (`IRCConnection` has one for
  connecting; `DCCTransfer` needed one for *both* directions, since either side of a DCC offer can
  simply never be answered).

## Startup diagnostics

Workspace throws a launched application's stderr away. `touch ~/.RatChat.trace` before launching
(from Workspace or `open`) to get the same startup narration `main.m`'s `NSLog` calls print, in a
file instead.
