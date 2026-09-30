# Host-side build & test (macOS/Linux).  The OPENSTEP build lives in Makefile.openstep.
# Flags approximate what gcc 2.7.2 will accept: strict C89, no // comments,
# no mixed declarations, no stdint.
CC      ?= cc
CFLAGS  = -std=c89 -pedantic -Wall -Wextra -Wdeclaration-after-statement \
          -Wno-long-long -Wno-unused-parameter -O2 -g -Icore
BUILD   = build
SANFLAGS =
# make SAN=1 test   -- build everything with AddressSanitizer + UBSan in build-san/
ifdef SAN
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
CFLAGS  += $(SANFLAGS)
BUILD   = build-san
endif

TERM_SRC = $(wildcard term/*.c)
TERM_OBJ = $(patsubst term/%.c,$(BUILD)/term_%.o,$(TERM_SRC))
CORE_SRC = $(wildcard core/*.c)
CORE_OBJ = $(patsubst core/%.c,$(BUILD)/core_%.o,$(CORE_SRC))

all: test

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/term_%.o: term/%.c $(wildcard term/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/core_%.o: core/%.c $(wildcard core/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_vt: tests/test_vt.c $(TERM_OBJ)
	$(CC) $(CFLAGS) tests/test_vt.c $(TERM_OBJ) -o $@

$(BUILD)/test_irc_parse: tests/test_irc_parse.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_irc_parse.c $(CORE_OBJ) -o $@

$(BUILD)/test_dcc: tests/test_dcc.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_dcc.c $(CORE_OBJ) -o $@

$(BUILD)/test_crypto: tests/test_crypto.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_crypto.c $(CORE_OBJ) -o $@

$(BUILD)/test_bignum: tests/test_bignum.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_bignum.c $(CORE_OBJ) -o $@

$(BUILD)/test_ecc: tests/test_ecc.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_ecc.c $(CORE_OBJ) -o $@

$(BUILD)/test_rsa: tests/test_rsa.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_rsa.c $(CORE_OBJ) -o $@

$(BUILD)/test_der: tests/test_der.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_der.c $(CORE_OBJ) -o $@

$(BUILD)/test_x509: tests/test_x509.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_x509.c $(CORE_OBJ) -o $@

$(BUILD)/test_tls_wire: tests/test_tls_wire.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_tls_wire.c $(CORE_OBJ) -o $@

$(BUILD)/test_tls_prf: tests/test_tls_prf.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_tls_prf.c $(CORE_OBJ) -o $@

$(BUILD)/test_tls_aead: tests/test_tls_aead.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_tls_aead.c $(CORE_OBJ) -o $@

$(BUILD)/test_tls: tests/test_tls.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_tls.c $(CORE_OBJ) -o $@

$(BUILD)/test_tls_pins: tests/test_tls_pins.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_tls_pins.c $(CORE_OBJ) -o $@

$(BUILD)/test_prims: tests/test_prims.c tests/prims_ref.h core/nacl.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_prims.c $(CORE_OBJ) -o $@

# Per-primitive cost of the TLS data path (record ciphers, hashes, HMAC, X25519) for before/after comparisons on
# the real machines; strict flags because it also has to build under Makefile.openstep's gcc 2.7.2.
$(BUILD)/bench_bulk: tools/bench_bulk.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tools/bench_bulk.c $(CORE_OBJ) -o $@

bench-bulk: $(BUILD)/bench_bulk
	$(BUILD)/bench_bulk

test: $(BUILD)/test_prims $(BUILD)/test_vt $(BUILD)/test_irc_parse $(BUILD)/test_dcc \
      $(BUILD)/test_crypto $(BUILD)/test_bignum $(BUILD)/test_ecc $(BUILD)/test_rsa $(BUILD)/test_der \
      $(BUILD)/test_x509 $(BUILD)/test_tls_wire $(BUILD)/test_tls_prf $(BUILD)/test_tls_aead $(BUILD)/test_tls \
      $(BUILD)/test_tls_pins
	$(BUILD)/test_prims
	$(BUILD)/test_vt
	$(BUILD)/test_irc_parse
	$(BUILD)/test_dcc
	$(BUILD)/test_crypto
	$(BUILD)/test_bignum
	$(BUILD)/test_ecc
	$(BUILD)/test_rsa
	$(BUILD)/test_der
	$(BUILD)/test_x509
	$(BUILD)/test_tls_wire
	$(BUILD)/test_tls_prf
	$(BUILD)/test_tls_aead
	$(BUILD)/test_tls
	$(BUILD)/test_tls_pins

lint:
	sh tools/lint_openstep.sh

# Syntax-check the Objective-C against the modern SDK (never linked or run).
check-objc:
	for f in app/*.m; do \
	  echo "check $$f"; \
	  $(CC) -fsyntax-only -x objective-c -fno-objc-arc -Wall -Wno-deprecated-declarations \
	    -Wdeclaration-after-statement -Wno-unused-parameter -Iterm -Iapp -Icore $$f || exit 1; \
	done

# Package the sources for transfer into the OPENSTEP VM.
#   dist/RATCHAT.TAR  plain ustar archive (extract with:  tar xf RATCHAT.TAR)
#   dist/RATCHAT.ISO  a CD image containing RATCHAT.TAR (attach it as a CD-ROM in the VM)
# -b 20 matters: see StepSSH's own Makefile for why (old tar implementations read archives in
# fixed 10240-byte records; a short final record makes their first read() look like premature EOF).
DISTFILES = README.md Makefile.openstep core term app tests tools
dist:
	mkdir -p dist
	COPYFILE_DISABLE=1 tar --format ustar -b 20 --exclude '*.o' --exclude '.DS_Store' \
	    -cf dist/RATCHAT.TAR $(DISTFILES)
	rm -rf dist/iso && mkdir -p dist/iso && cp dist/RATCHAT.TAR dist/iso/
	rm -f dist/RATCHAT.ISO dist/RATCHAT.iso dist/RATCHAT.iso.iso
	hdiutil makehybrid -iso -iso-volume-name RATCHAT -o dist/RATCHAT dist/iso >/dev/null
	f=$$(ls dist/RATCHAT.* | grep -iv 'RATCHAT.TAR' | head -1); mv "$$f" dist/RATCHAT.ISO
	rm -rf dist/iso
	@ls -l dist/RATCHAT.TAR dist/RATCHAT.ISO

# Drives a real AppController/IRCConnection/IRCChannelSession stack against a scripted fake IRC
# server (a real TCP listener on 127.0.0.1) -- the closest thing to pty_smoke.m StepTTY has, just
# against a fake IRC server instead of a real forked shell.
UI_SRC = app/AppController.m app/ConnectController.m app/DCCTransfer.m app/IRCChannelSession.m \
         app/IRCConnection.m app/TerminalView.m app/UIHelpers.m
irc-smoke:
	mkdir -p build
	for f in tests/irc_smoke.m $(UI_SRC); do \
	  $(CC) -c -x objective-c -fno-objc-arc -w -g -Iterm -Iapp -Icore $$f -o build/is_$$(basename $$f .m).o || exit 1; \
	done
	for f in term/*.c core/*.c; do $(CC) -c -w -g -Iterm -Icore $$f -o build/is_c_$$(basename $$f .c).o || exit 1; done
	$(CC) build/is_*.o -framework Cocoa -o build/irc_smoke
	build/irc_smoke

# Drives two real DCCTransfer instances (one sending, one receiving) against each other over a
# real 127.0.0.1 connection -- see the test file's own header for exactly what this covers versus
# test_dcc.c and irc_smoke.m.
dcc-smoke:
	mkdir -p build
	$(CC) -c -x objective-c -fno-objc-arc -w -g -Iterm -Iapp -Icore app/DCCTransfer.m -o build/ds_DCCTransfer.o
	$(CC) -c -w -g -Icore core/dcc.c -o build/ds_c_dcc.o
	$(CC) -c -x objective-c -fno-objc-arc -w -g -Iterm -Iapp -Icore tests/dcc_smoke.m -o build/ds_dcc_smoke.o
	$(CC) build/ds_*.o -framework Cocoa -o build/dcc_smoke
	build/dcc_smoke

# Confirms AppController gates a TLS connection attempt on a real, un-seeded RNG pool (showing
# the entropy-seeding panel and stashing the request) rather than either failing fast or silently
# under-seeding -- and that a plaintext connection is never gated on it at all. Must run in a
# fresh process, since core/rng.c's pool is global static state with no reset -- see the test
# file's own header.
entropy-gate-smoke:
	mkdir -p build
	for f in tests/entropy_gate_smoke.m $(UI_SRC); do \
	  $(CC) -c -x objective-c -fno-objc-arc -w -g -Iterm -Iapp -Icore $$f -o build/egs_$$(basename $$f .m).o || exit 1; \
	done
	for f in term/*.c core/*.c; do $(CC) -c -w -g -Iterm -Icore $$f -o build/egs_c_$$(basename $$f .c).o || exit 1; done
	$(CC) build/egs_*.o -framework Cocoa -o build/entropy_gate_smoke
	build/entropy_gate_smoke

clean:
	rm -rf build build-san

# Drives a real tls_session, as a real TCP client, through a full TLS 1.2 handshake against a
# REAL local `openssl s_server` (a temporary self-signed cert generated fresh each run) -- see
# the test file's own header for why this stands in for a byte-for-byte replay of a captured
# real handshake, which turns out not to be achievable with ordinary OpenSSL tooling.
tls-smoke:
	mkdir -p build
	openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj "/CN=localhost" \
	    -keyout build/tls_smoke.key -out build/tls_smoke.pem 2>/dev/null
	$(CC) -w -g -Icore tests/tls_smoke.c core/*.c -o build/tls_smoke
	build/tls_smoke

# The same real-server technique as tls-smoke, but through the actual app-layer wiring
# (IRCConnection's useTLS path, AppController's TLS pin store) instead of core/tls.c directly --
# a pre-seeded pin (the same SHA-256 core/tls_pins.c itself would compute) lets it run headless,
# since the real TLS_EV_CERT trust dialog is a genuinely modal NSRunAlertPanel otherwise.
irc-tls-smoke:
	mkdir -p build
	openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 -subj "/CN=localhost" \
	    -keyout build/irc_tls_smoke.key -out build/irc_tls_smoke.pem 2>/dev/null
	fp=$$(openssl x509 -in build/irc_tls_smoke.pem -outform DER | openssl dgst -sha256 -r | awk '{print $$1}'); \
	    printf "127.0.0.1 15901 %s\n" "$$fp" > build/irc_tls_pins.txt
	for f in tests/irc_tls_smoke.m $(UI_SRC); do \
	  $(CC) -c -x objective-c -fno-objc-arc -w -g -Iterm -Iapp -Icore $$f -o build/its_$$(basename $$f .m).o || exit 1; \
	done
	for f in term/*.c core/*.c; do $(CC) -c -w -g -Iterm -Icore $$f -o build/its_c_$$(basename $$f .c).o || exit 1; done
	$(CC) build/its_*.o -framework Cocoa -o build/irc_tls_smoke
	build/irc_tls_smoke 15901 build/irc_tls_smoke.pem build/irc_tls_smoke.key build/irc_tls_pins.txt

.PHONY: all test bench-bulk lint check-objc dist irc-smoke dcc-smoke tls-smoke irc-tls-smoke entropy-gate-smoke clean
