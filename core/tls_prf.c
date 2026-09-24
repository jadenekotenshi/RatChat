#include "tls_prf.h"
#include "hmac.h"
#include <string.h>

void tls_prf(const u8 *secret, size_t secret_len, const char *label,
             const u8 *seed, size_t seed_len, u8 *out, size_t out_len)
{
    u8 a[32];
    hmac_ctx h;
    size_t label_len = strlen(label);
    size_t done = 0;

    hmac_init(&h, HMAC_SHA256, secret, secret_len);      /* A(1) = HMAC(secret, label || seed) */
    hmac_update(&h, label, label_len);
    hmac_update(&h, seed, seed_len);
    hmac_final(&h, a);

    while (done < out_len) {
        u8 block[32];
        size_t n;

        hmac_init(&h, HMAC_SHA256, secret, secret_len);  /* HMAC(secret, A(i) || label || seed) */
        hmac_update(&h, a, sizeof(a));
        hmac_update(&h, label, label_len);
        hmac_update(&h, seed, seed_len);
        hmac_final(&h, block);

        n = out_len - done < sizeof(block) ? out_len - done : sizeof(block);
        memcpy(out + done, block, n);
        done += n;

        if (done < out_len) {                            /* A(i+1) = HMAC(secret, A(i)) */
            hmac_init(&h, HMAC_SHA256, secret, secret_len);
            hmac_update(&h, a, sizeof(a));
            hmac_final(&h, a);
        }
    }

    ssh_wipe(a, sizeof(a));
}
