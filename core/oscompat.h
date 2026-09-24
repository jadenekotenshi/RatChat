/*
 * oscompat.h -- prototypes (and a couple of missing types) that OPENSTEP 4.2's system headers
 * leave out.
 *
 * Its <unistd.h>, <sys/stat.h> etc. predate ANSI prototypes for several plain
 * POSIX calls, so gcc reports "implicit declaration".  Only functions that were
 * actually reported are listed here: redeclaring one the headers DO declare
 * could cause a "conflicting types" error.
 *
 * Include this AFTER every system header in a file.  It is empty unless the
 * OPENSTEP build (-DOPENSTEP) is in effect, so host builds are unaffected.
 * Argument types are int/pointer everywhere, which matches the i386 calling
 * convention whatever the headers' own typedefs (mode_t, pid_t) are.
 *
 * select()'s declaration below needs fd_set and struct timeval -- pulled in here directly
 * (<sys/types.h>, <sys/time.h>; harmless to re-include if the caller already did, headers guard
 * themselves) rather than left as a requirement on whatever else the including file happens to
 * include, since a file with no reason of its own to need select() (stepssh-keygen.c, say) would
 * otherwise fail on *this* header's own declaration instead. There is no <sys/select.h> on
 * OPENSTEP 4.2 to pull those two in together (that split is a POSIX.1-2001 convention, a good
 * decade newer).
 */
#ifndef SSH_OSCOMPAT_H
#define SSH_OSCOMPAT_H

#ifdef OPENSTEP
#include <sys/types.h>
#include <sys/time.h>
extern int close(int fd);
extern int getpid(void);
extern int chmod(const char *path, int mode);
extern int mkdir(const char *path, int mode);
extern int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout);
typedef int ssize_t;      /* no ssize_t at all: POSIX.1-1990 has it, but OPENSTEP 4.2 predates
                            * even that catching up in its own headers. int matches read()/write()'s
                            * actual i386 ABI return width here, same reasoning as the note above. */
/* getopt() itself works via the usual implicit-int-returning-function assumption (harmless: it
 * really does return int), but optarg/optind are variables, not functions -- there is no such
 * thing as an "implicit declaration" for those, so referencing them with no declaration in scope
 * at all is a hard compile error, not just a warning. */
extern char *optarg;
extern int optind;
extern int getopt(int argc, char **argv, const char *optstring);
extern int read(int fd, void *buf, int n);
extern int write(int fd, const void *buf, int n);
extern int isatty(int fd);
/* getlogin() returns a pointer -- unlike getopt()/read()/write() above, an implicit declaration
 * here is not harmless: gcc assumes it returns int, silently truncating the real pointer on any
 * platform where int and a pointer differ in size (the exact same class of bug strdup() risked
 * elsewhere in this codebase, not a hypothetical one -- gcc 2.7.2 reported it directly here as
 * "initialization makes pointer from integer without a cast"). */
extern char *getlogin(void);
extern int getuid(void);
#endif

#endif
