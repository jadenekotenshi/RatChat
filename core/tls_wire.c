#include "tls_wire.h"

int tls_put_u16(sbuf *b, u32 v)
{
    u8 buf[2];
    buf[0] = (u8)(v >> 8); buf[1] = (u8)v;
    return sb_put(b, buf, 2);
}

int tls_put_u24(sbuf *b, u32 v)
{
    u8 buf[3];
    buf[0] = (u8)(v >> 16); buf[1] = (u8)(v >> 8); buf[2] = (u8)v;
    return sb_put(b, buf, 3);
}

int tls_put_vec8(sbuf *b, const u8 *d, size_t n)
{
    if (n > 0xff || sb_put_u8(b, (u8)n) != 0) return -1;
    return n ? sb_put(b, d, n) : 0;
}

int tls_put_vec16(sbuf *b, const u8 *d, size_t n)
{
    if (n > 0xffff || tls_put_u16(b, (u32)n) != 0) return -1;
    return n ? sb_put(b, d, n) : 0;
}

int tls_put_vec24(sbuf *b, const u8 *d, size_t n)
{
    if (n > 0xffffff || tls_put_u24(b, (u32)n) != 0) return -1;
    return n ? sb_put(b, d, n) : 0;
}

u32 tls_get_u16(sreader *r)
{
    const u8 *p = sr_bytes(r, 2);
    return p ? ((u32)p[0] << 8 | (u32)p[1]) : 0;
}

u32 tls_get_u24(sreader *r)
{
    const u8 *p = sr_bytes(r, 3);
    return p ? ((u32)p[0] << 16 | (u32)p[1] << 8 | (u32)p[2]) : 0;
}

const u8 *tls_get_vec8(sreader *r, size_t *len)
{
    size_t n = sr_u8(r);
    const u8 *p = sr_bytes(r, n);
    *len = p ? n : 0;
    return p;
}

const u8 *tls_get_vec16(sreader *r, size_t *len)
{
    size_t n = (size_t)tls_get_u16(r);
    const u8 *p = sr_bytes(r, n);
    *len = p ? n : 0;
    return p;
}

const u8 *tls_get_vec24(sreader *r, size_t *len)
{
    size_t n = (size_t)tls_get_u24(r);
    const u8 *p = sr_bytes(r, n);
    *len = p ? n : 0;
    return p;
}
