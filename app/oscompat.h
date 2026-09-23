/*
 * oscompat.h -- prototypes (and a couple of missing macros) that OPENSTEP 4.2's system headers
 * leave out. Same idea as StepSSH's and StepTTY's own oscompat.h -- only entries actually needed
 * are listed here: redeclaring one the headers DO declare could cause a "conflicting types" error.
 *
 * Unlike StepTTY's own oscompat.h (which found its gaps by real-hardware trial and error),
 * everything here is carried over pre-confirmed from StepSSH's SSHSession.m, which already does
 * the exact same kind of thing this project's IRCConnection does -- open a raw BSD socket,
 * fcntl() it O_NONBLOCK, poll it with select(). StepSSH already paid for finding these the hard
 * way, and forgetting to copy them into a *new* file once already caused a real build break there
 * (PortForward.m, commit 0e0468e) -- so they are included here from the start rather than
 * rediscovered.
 *
 * Include this AFTER every system header in a file. It is empty unless the OPENSTEP build
 * (-DOPENSTEP) is in effect, so host builds are unaffected.
 */
#ifndef RC_OSCOMPAT_H
#define RC_OSCOMPAT_H

#ifdef OPENSTEP
#ifndef O_NONBLOCK
#define O_NONBLOCK O_NDELAY
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

/* Not declared under OPENSTEP despite <fcntl.h>/<sys/types.h> being included. */
extern int fcntl(int fd, int cmd, ...);
extern int select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);
#endif

#endif
