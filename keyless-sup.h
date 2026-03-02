#include "shim.h"
#include "openssl/x509.h"

char *b64_encode(const unsigned char *in, size_t inlen);

// inline CHAR8 nybble_hex(UINT8 v, BOOLEAN upper);
void bin_to_hex_buf(const UINT8 *in, UINTN len, CHAR8 *out, UINTN outcap, BOOLEAN upper);
// CHAR8 *bin_to_hex_alloc(const UINT8 *in, UINTN len, BOOLEAN upper);

CHAR8 *x509_to_der_b64(X509 *x);
int x509_equal(X509 *a, X509 *b);

const char *oid_sn_or_txt(const ASN1_OBJECT *o, char *buf, size_t bufsz);
CHAR8 *asn1_any_to_b64(const ASN1_TYPE *a);
