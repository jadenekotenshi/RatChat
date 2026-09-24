#ifndef SSH_RNG_H
#define SSH_RNG_H
#include "ssh_types.h"

/*
 * Entropy pool + hash DRBG.
 *
 * OPENSTEP 4.2 has no /dev/urandom that we can count on, so the pool tracks
 * how many bits of real entropy have been *credited* to it and refuses to
 * hand out bytes until it has at least SSH_RNG_MIN_BITS.  Sources:
 *   - /dev/urandom or /dev/random when present          (credited 256 bits)
 *   - a persistent seed file, renewed on every load     (credited 256 bits)
 *   - UI event timing supplied by the application       (credited ~1 bit each)
 *   - network arrival timing                            (credited ~1 bit each)
 *   - clock/pid/environment "junk"                      (credited 0 bits)
 * Only the first four count.  The junk is mixed in anyway; it costs nothing.
 */
#define SSH_RNG_MIN_BITS 256

/* Mix data in and credit `bits` bits of entropy (0 is fine). */
void ssh_rng_add(const void *data, size_t len, int bits);
/* Mix in the current high-resolution time, crediting `bits` (use for events). */
void ssh_rng_add_timing(int bits);
/* Try /dev/urandom and /dev/random.  Returns bits credited (0 if neither exists). */
int  ssh_rng_seed_system(void);
/* Load then immediately replace the seed file.  Returns bits credited. */
int  ssh_rng_load_seed(const char *path);
int  ssh_rng_save_seed(const char *path);

int  ssh_rng_credited(void);
int  ssh_rng_ready(void);
/* Returns 0 on success, -1 if the pool has not been credited enough. */
int  ssh_rng_bytes(void *out, size_t len);

#endif
