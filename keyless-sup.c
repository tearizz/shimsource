#include "shim.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
// maybe not used
#include "openssl/asn1.h"
#include "openssl/buffer.h"

// Base64 encode using OpenSSL BIO
CHAR8 *b64_encode(const unsigned char *in, size_t inlen) {
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *mem = BIO_new(BIO_s_mem());
	if (!b64 || !mem) { BIO_free_all(b64); BIO_free_all(mem); return NULL; }
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	b64 = BIO_push(b64, mem);
	if (BIO_write(b64, in, (int)inlen) != (int)inlen) { BIO_free_all(b64); return NULL; }
	if (BIO_flush(b64) != 1) { BIO_free_all(b64); return NULL; }
	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(b64, &bptr);
    CHAR8 *out = NULL;
    if (bptr && bptr->length) {
        out = AllocatePool((UINTN)bptr->length + 1);
        if (out) {
            CopyMem(out, bptr->data, (UINTN)bptr->length);
            out[(UINTN)bptr->length] = '\0';
        }
    }
	BIO_free_all(b64);
    return out;
}

/*
    Nybble(nibble) half byte(4bit)
    1 byte = 2 nybble 
    1 nybble = 1 hex
    1 byte = 2 nybble = 2hex
*/
static inline CHAR8 nybble_hex(UINT8 v, BOOLEAN upper){
    return (v < 10) ? ('0' + v) : ((upper ? 'A' : 'a') + (v - 10));
}

// Binary(bytes) to hex 
void bin_to_hex_buf(const UINT8 *in, UINTN len, CHAR8 *out, UINTN outcap, BOOLEAN upper){
    if (!out || outcap == 0) return;
    if (!out || len == 0) {
        out[0] = '\0';
        return;
    }

    UINTN need = len * 2 + 1;
    if (outcap < need) {
        len = (outcap - 1) /2;
    }

    for (UINTN i = 0, j = 0; i < len; i++){
        UINT8 b = in[i];
        out[j++] = nybble_hex((b>>4) & 0x0F, upper);
        out[j++] = nybble_hex(b & 0x0F, upper);
        out[j] = '\0';
    }
}
// static CHAR8 *bin_to_hex_alloc(const UINT8 *in, UINTN len, BOOLEAN upper){
//     UINTN need = len*2 + 1;
//     CHAR8 *out = AllocatePool(need);
//     if (!out) 
//         return NULL;

//     bin_to_hex_buf(in,len,out,need,upper);
//     return out;
// }

// x509_to_der_b64 convert X.509 to base64 DER
CHAR8 *x509_to_der_b64(X509 *x){
    int len = i2d_X509(x,NULL);
    if(len<0) return NULL;

    unsigned char *der = AllocatePool(len);
    if(!der) return NULL;

    unsigned char *p = der;
    if (i2d_X509(x,&p) != len) {
        FreePool(der);
        return NULL;
    }

    CHAR8 *b64 = (CHAR8 *)b64_encode(der, (UINTN)len);
    FreePool(der);

    return b64;
}

// compare two x509 by DER equality
int x509_equal(X509 *a, X509 *b){
    int la = i2d_X509(a, NULL);
    int lb = i2d_X509(b, NULL);
    if (la <= 0 || lb <= 0 || la != lb)
        return 0;
    
    unsigned char *da = AllocatePool(la);
    unsigned char *db = AllocatePool(lb);
    if(!da || !db){
        if (da)
            FreePool(db);
        if (db)
            FreePool(db);
        return 0;
    }

    unsigned char *pa = da;
    unsigned char *pb = db;
    i2d_X509(a, &pa);
    i2d_X509(b, &pb);

    int eq = (CompareMem(da,db,la) == 0);
    FreePool(da);
    FreePool(db);
   
    return eq;
}

const char *oid_sn_or_txt(const ASN1_OBJECT *o, char *buf, size_t bufsz){
    int nid = OBJ_obj2nid((ASN1_OBJECT *)o);
    const char *sn = OBJ_nid2sn(nid);
    if(sn)
        return sn;
    OBJ_obj2txt(buf, (int)bufsz, o, 1);
    return buf;
}

CHAR8 *asn1_any_to_b64(const ASN1_TYPE *a){
    if(!a) return NULL;
    
    const unsigned char *p = NULL;
    
    int len = i2d_ASN1_TYPE((ASN1_TYPE *)a, NULL);
    if (len <= 0) return NULL;
    unsigned char *der = AllocatePool(len);
    if (!der) return NULL;
    p = der;
    
    if (i2d_ASN1_TYPE((ASN1_TYPE *)a, (unsigned char **)&p) != len){
        FreePool(der);
        return NULL;
    }

    CHAR8 *b64 = b64_encode(der, (UINTN)len);
    FreePool(der);
    return b64;
}