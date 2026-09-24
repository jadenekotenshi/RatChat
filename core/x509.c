#include "x509.h"
#include <string.h>

static const u8 OID_RSA[]  = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const u8 OID_EC[]   = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const u8 OID_P256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const u8 OID_P384[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const u8 OID_P521[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
static const u8 OID_CN[]   = { 0x55, 0x04, 0x03 };

void x509_cert_init(x509_cert *c)
{
    memset(c, 0, sizeof(*c));
    rsa_pub_init(&c->rsa);
    ec_point_init(&c->ec_pub);
}

void x509_cert_free(x509_cert *c)
{
    rsa_pub_free(&c->rsa);
    ec_point_free(&c->ec_pub);
}

static int curve_from_oid(const u8 *oid, size_t l)
{
    if (der_oid_eq(oid, l, OID_P256, sizeof(OID_P256))) return EC_P256;
    if (der_oid_eq(oid, l, OID_P384, sizeof(OID_P384))) return EC_P384;
    if (der_oid_eq(oid, l, OID_P521, sizeof(OID_P521))) return EC_P521;
    return -1;
}

/* ECParameters as found in a real-world certificate's SPKI: a named-curve OID. (The explicit
 * form -- an inline SEQUENCE spelling out p/a/b/G/n -- exists in the ASN.1 but every CA and
 * every TLS server in practice uses named curves; unlike ssh_key.c's own PEM-key parser, which
 * does support explicit parameters as a private-key head start, this deliberately does not.) */
static int curve_from_params(const u8 *p, size_t len)
{
    const u8 *end = p + len, *oid;
    size_t ol;
    if (len == 0 || p[0] != 0x06 || der_expect(&p, end, 0x06, &oid, &ol) != 0) return -1;
    return curve_from_oid(oid, ol);
}

/* Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue{OID, ANY}).
 * Best-effort only: the first commonName attribute found wins (and only if it fits cn_cap);
 * anything that fails to parse cleanly just leaves cn as whatever was already found, never
 * fails the certificate as a whole. */
static void extract_cn(const u8 *name, size_t len, char *cn, size_t cn_cap)
{
    const u8 *p = name, *end = name + len;
    cn[0] = '\0';
    while (p < end) {
        const u8 *rdn, *rdn_end;
        if (der_enter(&p, end, 0x31, &rdn, &rdn_end) != 0) return;
        while (rdn < rdn_end) {
            const u8 *atv, *atv_end, *oid, *val;
            size_t ol, vl;
            int tag;
            if (der_enter(&rdn, rdn_end, 0x30, &atv, &atv_end) != 0) return;
            if (der_expect(&atv, atv_end, 0x06, &oid, &ol) != 0) continue;
            if (der_read(&atv, atv_end, &tag, &val, &vl) != 0) continue;
            if (cn[0] == '\0' && vl < cn_cap && der_oid_eq(oid, ol, OID_CN, sizeof(OID_CN))) {
                memcpy(cn, val, vl);
                cn[vl] = '\0';
            }
        }
    }
}

int x509_parse_leaf(const u8 *der, size_t len, x509_cert *out, const char **err)
{
    const u8 *p = der, *end = der + len;
    const u8 *cert, *cert_end, *tbs, *tbs_end;
    const u8 *v, *subject, *validity, *validity_end;
    const u8 *spki, *spki_end, *alg, *alg_end, *oid, *bits;
    size_t l, bl;
    int tag, unused_bits;

    *err = "corrupt certificate";

    if (der_enter(&p, end, 0x30, &cert, &cert_end) != 0) return -1;         /* Certificate */
    if (der_enter(&cert, cert_end, 0x30, &tbs, &tbs_end) != 0) return -1;   /* TBSCertificate */

    /* version [0] EXPLICIT INTEGER DEFAULT v1 is OPTIONAL; if the next TLV isn't tagged 0xa0,
     * it was actually serialNumber, so back up and read it as that instead. */
    {
        const u8 *save = tbs;
        if (der_read(&tbs, tbs_end, &tag, &v, &l) != 0) return -1;
        if (tag != 0xa0) tbs = save;
    }
    if (der_read(&tbs, tbs_end, &tag, &v, &l) != 0) return -1;              /* serialNumber, opaque */
    if (der_read(&tbs, tbs_end, &tag, &v, &l) != 0) return -1;              /* signature AlgorithmIdentifier, opaque */
    if (der_read(&tbs, tbs_end, &tag, &v, &l) != 0) return -1;              /* issuer Name, opaque */

    if (der_enter(&tbs, tbs_end, 0x30, &validity, &validity_end) != 0) return -1;
    if (der_read(&validity, validity_end, &tag, &v, &l) != 0) return -1;
    if (tag == 0x17) { if (der_utctime(v, l, &out->not_before) != 0) { *err = "bad notBefore time"; return -1; } }
    else if (tag == 0x18) { if (der_generalizedtime(v, l, &out->not_before) != 0) { *err = "bad notBefore time"; return -1; } }
    else { *err = "bad notBefore time"; return -1; }
    if (der_read(&validity, validity_end, &tag, &v, &l) != 0) return -1;
    if (tag == 0x17) { if (der_utctime(v, l, &out->not_after) != 0) { *err = "bad notAfter time"; return -1; } }
    else if (tag == 0x18) { if (der_generalizedtime(v, l, &out->not_after) != 0) { *err = "bad notAfter time"; return -1; } }
    else { *err = "bad notAfter time"; return -1; }

    if (der_expect(&tbs, tbs_end, 0x30, &subject, &l) != 0) { *err = "bad subject name"; return -1; }
    extract_cn(subject, l, out->cn, sizeof(out->cn));

    /* SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier { OID, params ANY }, BIT STRING } */
    if (der_enter(&tbs, tbs_end, 0x30, &spki, &spki_end) != 0) { *err = "bad SubjectPublicKeyInfo"; return -1; }
    if (der_enter(&spki, spki_end, 0x30, &alg, &alg_end) != 0) { *err = "bad SubjectPublicKeyInfo algorithm"; return -1; }
    if (der_expect(&alg, alg_end, 0x06, &oid, &l) != 0) { *err = "bad SubjectPublicKeyInfo algorithm OID"; return -1; }
    if (der_bitstring(&spki, spki_end, &bits, &bl, &unused_bits) != 0 || unused_bits != 0) {
        *err = "bad SubjectPublicKey";
        return -1;
    }

    if (der_oid_eq(oid, l, OID_RSA, sizeof(OID_RSA))) {
        const u8 *rp = bits, *rend = bits + bl, *seq, *seq_end, *nv, *ev;
        size_t nl, el;
        out->key_type = X509_KEY_RSA;
        if (der_enter(&rp, rend, 0x30, &seq, &seq_end) != 0 || rp != rend) { *err = "bad RSAPublicKey"; return -1; }
        if (der_int(&seq, seq_end, &nv, &nl) != 0 || der_int(&seq, seq_end, &ev, &el) != 0 || seq != seq_end) {
            *err = "bad RSAPublicKey";
            return -1;
        }
        if (bn_from_bytes(&out->rsa.n, nv, nl) != 0 || bn_from_bytes(&out->rsa.e, ev, el) != 0) {
            *err = "bad RSAPublicKey";
            return -1;
        }
    } else if (der_oid_eq(oid, l, OID_EC, sizeof(OID_EC))) {
        const ec_curve *c;
        out->key_type = X509_KEY_EC;
        out->curve = curve_from_params(alg, (size_t)(alg_end - alg));
        if (out->curve < 0) { *err = "unsupported or missing elliptic curve"; return -1; }
        c = ec_curve_get(out->curve);
        if (!c || ec_decode_point(c, bits, bl, &out->ec_pub) != 0) { *err = "bad EC public key point"; return -1; }
    } else {
        *err = "unsupported public key algorithm";
        return -1;
    }

    out->der = der;
    out->der_len = len;
    *err = "ok";
    return 0;
}
