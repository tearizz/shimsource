// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
 * Simplified Authenticode data extraction:
 * - Read raw on-disk bytes
 * - Parse PE header to locate Security Directory  
 * - Compute Authenticode hash over file bytes excluding Security Directory
 * - Parse PKCS#7 from Security Directory
 * - Extract SpcIndirectDataContent (SEQ content) and verify messageDigest
 * - Extract SignedAttributes DER, signature, and certificate for external verification
 */

#include "shim.h"
#include "keyless-sign.h"
#include "keyless-sup.h"
#include "http-request.h"
#include "include/pe.h"

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>

static int ascii_eq(const CHAR8 *a, const CHAR8 *b) {
   	while (*a && *b) {
   		if (*a != *b) return 0;
       		a++; b++;
    	}
   	return *a == 0 && *b == 0;
}

static EFI_STATUS read_file_ondisk(EFI_HANDLE device, CHAR16 *path, void **buf, UINTN *sz)
{
	EFI_STATUS efi_status;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
	EFI_FILE_PROTOCOL *root = NULL, *fh = NULL;
	EFI_FILE_INFO *info = NULL;
	UINTN infosz = sizeof(EFI_FILE_INFO);

	*buf = NULL;
	*sz = 0;

	efi_status = BS->HandleProtocol(device, &EFI_SIMPLE_FILE_SYSTEM_GUID, (void **)&fs);
	if (EFI_ERROR(efi_status))
		return efi_status;

	efi_status = fs->OpenVolume(fs, &root);
	if (EFI_ERROR(efi_status))
		return efi_status;

	efi_status = root->Open(root, &fh, path, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(efi_status))
		goto done;

	info = AllocatePool(infosz);
	if (!info) {
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	efi_status = fh->GetInfo(fh, &EFI_FILE_INFO_GUID, &infosz, info);
	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(info);
		info = AllocatePool(infosz);
		if (!info) {
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
		efi_status = fh->GetInfo(fh, &EFI_FILE_INFO_GUID, &infosz, info);
	}
	if (EFI_ERROR(efi_status))
		goto done;

	*sz = info->FileSize;
	*buf = AllocatePool(*sz);
	if (!*buf) {
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	efi_status = fh->Read(fh, sz, *buf);

done:
	if (fh) fh->Close(fh);
	if (root) root->Close(root);
	if (info) FreePool(info);
	if (EFI_ERROR(efi_status) && *buf) {
		FreePool(*buf);
		*buf = NULL;
		*sz = 0;
	}
	return efi_status;
}

static UINTN hash_to_hex(int md_nid, const unsigned char *buf, size_t len, CHAR8 outhex[], size_t outhexsz)
{
	UINT8 tmp[SHA256_DIGEST_SIZE];
	UINTN tmplen = 0;

	if (md_nid == NID_sha256) {
		SHA256(buf, len, tmp);
		tmplen = SHA256_DIGEST_SIZE;
	} else if (md_nid == NID_sha1) {
		SHA1(buf, len, tmp);
		tmplen = SHA1_DIGEST_SIZE;
	} else {
		return 0;
	}
	bin_to_hex_buf(tmp, tmplen, outhex, outhexsz, FALSE);
	return tmplen;
}

static void show_oid(ASN1_OBJECT *asn1_str) {
	const ASN1_OBJECT *obj = asn1_str;
	int nid = OBJ_obj2nid(obj);
	const char *sn = (nid != NID_undef) ? OBJ_nid2sn(nid) : NULL;
	char oid_txt[128] = {0};

	OBJ_obj2txt(oid_txt, sizeof(oid_txt),obj, 1);

	console_print(L"ContentType: NID=%d  name=%a  oid=%a\n",
		nid, sn?sn:"NID_undef",oid_txt);

}

/*
 * Extract data for external verification:
 * - Verify messageDigest matches SEQ content hash
 * - Extract SignedAttributes DER (base64) - the complete payload
 * - Extract signature (base64)
 * - Extract certificate (base64)
 */
static BOOLEAN extract_verification_data(PKCS7 *p7, const UINT8 *sha256,
	const UINT8 *sha1,
	CHAR8 **out_signed_attrs_b64,
	CHAR8 **out_sig_b64,
	CHAR8 **out_cert_b64)
{
	if (!p7 || !PKCS7_type_is_signed(p7))
		return FALSE;

	/* Initialize output pointers to NULL if provided */
	if (out_signed_attrs_b64) *out_signed_attrs_b64 = NULL;
	if (out_sig_b64) *out_sig_b64 = NULL;
	if (out_cert_b64) *out_cert_b64 = NULL;

	if (p7 && p7->type) {
		show_oid(p7->type);
		show_oid(p7->d.sign->contents->type);
	} 	

	PKCS7_SIGNED *sd = p7->d.sign;
	if (!sd || !sd->signer_info || sk_PKCS7_SIGNER_INFO_num(sd->signer_info) <= 0)
		return FALSE;

	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sd->signer_info, 0);
	if (!si)
		return FALSE;

	// md_nid: message digest algorithm numeric identifier
	int md_nid = OBJ_obj2nid(si->digest_alg->algorithm);
	const char *md_name = OBJ_nid2sn(md_nid);
	if (!md_name) md_name = "unknown";

	// Get Content ( = SpcIndirectDataContent in AuthentiCode)
	ASN1_STRING *astr = NULL;
	if (sd->contents && sd->contents->d.other && sd->contents->d.other->value.asn1_string)
		astr = sd->contents->d.other->value.asn1_string;
	if (!astr || !astr->data || astr->length <= 0) {
		// console_print(L"[EXTRACT] Content of signedData miss \n");
		return FALSE;
	}

	// base contains DER encoding of the SpcIndirectDataContent
	const unsigned char *base = astr->data;
	long blen = astr->length;

	const unsigned char *p = base; 
	long rem = blen; 
	int tag = 0, xclass = 0; 
	long len = 0;
	
	int r = ASN1_get_object(&p, &len, &tag, &xclass, rem);
	if (r & 0x80 || tag != V_ASN1_SEQUENCE || len < 0 || (p + len) > (base + blen)) {
		// console_print(L"[EXTRACT] Invalid SpcIndirectDataContent SEQUENCE\n");
		return FALSE;
	}

	// SEQ content = SpcIndirectDataContent content bytes
	const unsigned char *seq_content = p;
	size_t seq_content_len = (size_t)len;

	// Compute hash of SEQ content
	CHAR8 seq_hash_hex[SHA256_DIGEST_SIZE*2+1]; 
	seq_hash_hex[0] = 0;
	(void)hash_to_hex(md_nid, seq_content, seq_content_len, seq_hash_hex, sizeof(seq_hash_hex));

	// Get messageDigest from SignedAttributes
	const ASN1_TYPE *tmd = PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
	if (!tmd || tmd->type != V_ASN1_OCTET_STRING) {
		// console_print(L"[EXTRACT] messageDigest attr missing\n");
		return FALSE;
	}
	
	CHAR8 md_attr_hex[SHA256_DIGEST_SIZE*2+1]; 
	md_attr_hex[0] = 0;
	bin_to_hex_buf(tmd->value.octet_string->data, (UINTN)tmd->value.octet_string->length, 
		       md_attr_hex, sizeof(md_attr_hex), FALSE);


	// Compare SEQ content hash with messageDigest
	BOOLEAN md_match = ascii_eq(md_attr_hex, seq_hash_hex);

	if (!md_match) {
		// console_print(L"[EXTRACT] Content verification failed\n");
		return FALSE;
	}

	// 解析SpcIndirectDataContent 中的DigestInfo， 取出内部的
	// 文件哈希(DigestInfo.digest) 并与 generate_hash 的结果sha256/sha1比较
	// SpcIndirectDataContent ::= SEQUENCE { SpcAttributeTypeAndOptionalValue, DigestInfo }
	const unsigned char *q = seq_content;
	long rem2 = (long)seq_content_len;
	int ftag = 0, fxclass = 0;
	long flen = 0;
	int rr = ASN1_get_object(&q, &flen, &ftag, &fxclass, rem2);
	if (rr & 0x80 || flen < 0 || (q + flen) > (seq_content + seq_content_len)) {
		// console_print( L"[EXTRACT] Parse first file of SpcIndirectDataContent failed\n");
	} else {
		// q points to first field content; 
		// compute total bytes used by first filed(header+content)
		size_t first_hdr_len = (size_t)(q - seq_content);
		size_t first_total = first_hdr_len + (size_t)flen;
		if (first_total >= seq_content_len) {
			// console_print(L"[EXTRACT] no room for DigestInfo\n");
		} else {
			const unsigned char *digptr = seq_content + first_total;
			long dig_len = (long)(seq_content_len - first_total);
			const unsigned char *tmp = digptr;
			X509_SIG *di = d2i_X509_SIG(NULL, &tmp, dig_len);
			if (!di) {
				// console_print(L"[EXTRACT] failed to parse DigestInfo\n");
			} else {
				// embedded digest bytes and length - use accessors.
				// Newer OpenSSL exposes X509_SIG_get0 and ASN1_STRING_get0_data;
				// older versions need to access fields / use ASN1_STRING_data.
				const unsigned char *embed = NULL;
				int embed_len = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				/* OpenSSL 1.1.0+ */
				const ASN1_OCTET_STRING *digest_asn1 = NULL;
				X509_SIG_get0(di, NULL, &digest_asn1);
				if (digest_asn1) {
					embed = ASN1_STRING_get0_data((const ASN1_STRING *)digest_asn1);
					embed_len = ASN1_STRING_length((const ASN1_STRING *)digest_asn1);
				}
#else
				/* Older OpenSSL: access struct field and use ASN1_STRING_data */
				ASN1_OCTET_STRING *digest_asn1 = NULL;
				/* X509_SIG layout historically exposes .digest */
				digest_asn1 = di->digest;
				if (digest_asn1) {
					embed = ASN1_STRING_data(digest_asn1);
					embed_len = ASN1_STRING_length(digest_asn1);
				}
#endif
				
				// Decide which file hash to compare against by length
				BOOLEAN file_match = FALSE;
				if (embed_len == SHA256_DIGEST_LENGTH && sha256 && embed) {
					file_match = (memcmp(embed, sha256, SHA256_DIGEST_SIZE) == 0);
				} else if (embed_len == SHA1_DIGEST_SIZE && sha1 && embed) {
					file_match = (memcmp(embed, sha1, SHA1_DIGEST_SIZE) == 0);
				} else {
					// embed_len(digest len) unknown or file hash not computed
					return false;
				}
				X509_SIG_free(di);
				if (!file_match) {
					// file hash mismatch DigestInfo mismatch\n");
					return false;
				}
			}
		}
	}


	// Extract complete SignedAttributes DER (base64) - this is the payload for signature verification
	if (si->auth_attr) {
		
		// Use BIO to manually encode SignedAttributes as DER
		BIO *bio = BIO_new(BIO_s_mem());
		if (bio) {
			// Write SET tag and length
			unsigned char *buf = NULL;
			long len = 0;
			
			// First, calculate total length needed
			int total_len = 0;
			for (int i = 0; i < sk_X509_ATTRIBUTE_num(si->auth_attr); i++) {
				X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(si->auth_attr, i);
				unsigned char *attr_der = NULL;
				int attr_len = i2d_X509_ATTRIBUTE(attr, &attr_der);
				if (attr_len > 0) {
					total_len += attr_len;
					OPENSSL_free(attr_der);
				}
			}
			
			if (total_len > 0) {
				// Write SET tag
				BIO_write(bio, "\x31", 1);
				
				// Write length (simplified - assumes < 128 bytes)
				if (total_len < 128) {
					BIO_write(bio, &total_len, 1);
				} else {
					// For longer lengths, use long form
					unsigned char len_bytes[4];
					int len_bytes_count = 0;
					int temp_len = total_len;
					while (temp_len > 0) {
						len_bytes[len_bytes_count++] = temp_len & 0xFF;
						temp_len >>= 8;
					}
					BIO_write(bio, &(unsigned char){0x80 | len_bytes_count}, 1);
					for (int i = len_bytes_count - 1; i >= 0; i--) {
						BIO_write(bio, &len_bytes[i], 1);
					}
				}
				
				// Write each attribute
				for (int i = 0; i < sk_X509_ATTRIBUTE_num(si->auth_attr); i++) {
					X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(si->auth_attr, i);
					unsigned char *attr_der = NULL;
					int attr_len = i2d_X509_ATTRIBUTE(attr, &attr_der);
					if (attr_len > 0 && attr_der) {
						BIO_write(bio, attr_der, attr_len);
						OPENSSL_free(attr_der);
					}
				}
				
				// Get the DER data
				len = BIO_get_mem_data(bio, &buf);
				if (len > 0 && buf) {
					/* Convert to base64 and return to caller (do not free here) */
					CHAR8 *tmp_signed_attrs_b64 = (CHAR8 *)b64_encode(buf, len);
					if (tmp_signed_attrs_b64) {
						if (out_signed_attrs_b64)
							*out_signed_attrs_b64 = tmp_signed_attrs_b64;
						else
							FreePool(tmp_signed_attrs_b64);
					}
				}
			}
			BIO_free(bio);
		}
	}

	// Extract signature (base64)
	if (si->enc_digest && si->enc_digest->data && si->enc_digest->length > 0) {
		CHAR8 *tmp_sig_b64 = (CHAR8 *)b64_encode(si->enc_digest->data, (UINTN)si->enc_digest->length);
		if (tmp_sig_b64) {
			if (out_sig_b64)
				*out_sig_b64 = tmp_sig_b64;
			else
				FreePool(tmp_sig_b64);
		}
	}

	// Extract certificate (base64)
	STACK_OF(X509) *signers = PKCS7_get0_signers(p7, NULL, 0);
	X509 *signer = (signers && sk_X509_num(signers) > 0) ? sk_X509_value(signers, 0) : NULL;
	if (signer) {
		unsigned char *cert_der = NULL;
		int cert_len = i2d_X509(signer, &cert_der);
		if (cert_len > 0 && cert_der) {
			CHAR8 *tmp_cert_b64 = (CHAR8 *)b64_encode(cert_der, cert_len);
			if (tmp_cert_b64) {
				if (out_cert_b64)
					*out_cert_b64 = tmp_cert_b64;
				else
					FreePool(tmp_cert_b64);
			}
			OPENSSL_free(cert_der);
		}
	}
	if (signers) sk_X509_free(signers);

	return TRUE;
}


static EFI_STATUS osign_extract_data(EFI_HANDLE image_handle, CHAR16 *path,
CHAR8 **data, UINTN *datasize, PE_COFF_LOADER_IMAGE_CONTEXT *ctx)
{
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE *li = NULL;

	efi_status = BS->HandleProtocol(image_handle, &EFI_LOADED_IMAGE_GUID,
		(void **)&li);
	if (EFI_ERROR(efi_status) || !li){
		return efi_status;
	}

	/* read_file_ondisk expects a void** for the buffer pointer */
	*data = NULL;
	*datasize = 0;
	efi_status = read_file_ondisk(li->DeviceHandle, path, (void **)data, datasize);
	if (EFI_ERROR(efi_status)) {
		return efi_status;
	}

	/* pass the actual buffer and size (data and datasize are pointers) */
	efi_status = read_header(*data, (unsigned)(*datasize), ctx, false);
	if (EFI_ERROR(efi_status)) {
		goto out;
	}
	if (!ctx->SecDir || ctx->SecDir->Size == 0) {
		efi_status = EFI_NOT_FOUND;
		goto out;
	}

out:
	/* Caller is responsible for freeing *data */
	return efi_status;
}


EFI_STATUS osign_parse_pkcs7(
	char *data, UINTN datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT ctx,
	CHAR8 **out_payload, 
	CHAR8 **out_signature, CHAR8 **out_certificate){

	EFI_STATUS efi_status;
	
	UINTN start = ctx.SecDir->VirtualAddress;
	UINTN size	= ctx.SecDir->Size;
	UINTN end	= start + size;

	if (end > datasize) {
		efi_status = EFI_INVALID_PARAMETER;
		goto out;
	}
	UINTN effective_size = end <= datasize ? end : datasize;

	UINT8 sha1[SHA1_DIGEST_SIZE];
	UINT8 sha256[SHA256_DIGEST_SIZE];
	efi_status = generate_hash(data, 
		(unsigned)effective_size, &ctx, sha256, sha1);
	if (EFI_ERROR(efi_status)) {
		goto out;
	}

	// Locate last PKCS#7 record in SecDir	
	ssize_t last_off = -1;
	size_t	offset = 0;
	while (offset < size) {
		const WIN_CERTIFICATE_EFI_PKCS *w =
			(const WIN_CERTIFICATE_EFI_PKCS *)ImageAddress(data, datasize, start + offset);
		if (!w)
			break;
		UINT32 wlen = w->Hdr.dwLength;
		if (wlen < sizeof(w->Hdr) || wlen > size - offset) {
			break;
		}

		if (w->Hdr.wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA)
			last_off = (ssize_t)offset;
		offset = ALIGN_VALUE(offset + wlen, 8);
	}
	if (last_off < 0) {
		efi_status = EFI_NOT_FOUND;
		goto out;
	}	

	const WIN_CERTIFICATE_EFI_PKCS *sig =
		(const WIN_CERTIFICATE_EFI_PKCS *)ImageAddress(data, datasize, start + (size_t)last_off);
	const unsigned char *p = sig->CertData;
	long der_len = (long)(sig->Hdr.dwLength - sizeof(sig->Hdr));

	PKCS7 *p7 = d2i_PKCS7(NULL, &p, der_len);
	if (!p7 || !PKCS7_type_is_signed(p7)) {
		if (p7) PKCS7_free(p7);
		efi_status = EFI_COMPROMISED_DATA;
		goto out;
	}

	/* Collect base64 outputs from extraction and free them after use */
	CHAR8 *signed_attrs_b64 = NULL;
	CHAR8 *sig_b64 = NULL;
	CHAR8 *cert_b64 = NULL;

	BOOLEAN ok = extract_verification_data(p7, sha256, sha1,
										   &signed_attrs_b64,
										   &sig_b64,
										   &cert_b64);

	PKCS7_free(p7);

	if (out_payload){
		*out_payload = signed_attrs_b64;
		signed_attrs_b64 = NULL;
	}
	if (out_signature){
		*out_signature = sig_b64;
		sig_b64 = NULL;
	}
	if (out_certificate){
		*out_certificate = cert_b64;
		cert_b64 = NULL;
	}
	if (signed_attrs_b64) FreePool(signed_attrs_b64);
	if (sig_b64) FreePool(sig_b64);
	if (cert_b64) FreePool(cert_b64);

	efi_status = ok ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;

out:
	return efi_status;
}

// extract_image_data removed (unused); keep osign_extract_data / osign_parse_pkcs7 instead.

/* Decode cert (base64 DER) and return public key PEM as allocated CHAR8*.
 * Caller must FreePool() the returned pointer. Returns NULL on error.
 */
CHAR8 *
cert_b64_to_pubkey_pem(const CHAR8 *cert_b64)
{
    if (!cert_b64) return NULL;

    /* estimate DER max size and allocate temporary buffer */
    size_t b64len = AsciiStrLen((const char *)cert_b64);
    int der_max = (int)((b64len * 3) / 4 + 16);
    unsigned char *der = AllocatePool(der_max);
    if (!der) return NULL;

    /* Base64 decode using OpenSSL BIO */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void *)cert_b64, (int)AsciiStrLen((const char *)cert_b64));
    if (!b64 || !bmem) {
        if (b64) BIO_free(b64);
        if (bmem) BIO_free(bmem);
        FreePool(der);
        return NULL;
    }
    /* handle no-newline base64 input */
#ifdef BIO_FLAGS_BASE64_NO_NL
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
#endif
    bmem = BIO_push(b64, bmem);
    int der_len = BIO_read(bmem, der, der_max);
    BIO_free_all(bmem);
    if (der_len <= 0) {
        FreePool(der);
        return NULL;
    }

    /* Parse X509 from DER bytes */
    const unsigned char *p = der;
    X509 *x = d2i_X509(NULL, &p, der_len);
    FreePool(der);
    if (!x) return NULL;

    /* Extract public key (EVP_PKEY) */
    EVP_PKEY *pkey = X509_get_pubkey(x);
    X509_free(x);
    if (!pkey) return NULL;

    /* Write public key to PEM in memory BIO */
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (!PEM_write_bio_PUBKEY(out, pkey)) {
        BIO_free(out);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    EVP_PKEY_free(pkey);

    /* Extract PEM data from BIO and copy to AllocatePool buffer */
    char *pem_ptr = NULL;
    long pem_len = BIO_get_mem_data(out, &pem_ptr);
    if (pem_len <= 0 || !pem_ptr) {
        BIO_free(out);
        return NULL;
    }
    CHAR8 *ret = AllocatePool((UINTN)pem_len + 1);
    if (ret) {
        CopyMem(ret, pem_ptr, (UINTN)pem_len);
        ret[pem_len] = 0;
    }
    BIO_free(out);
    return ret;
}

BOOLEAN
osign_verify(EFI_HANDLE image_handle,CHAR16* target_path)
{
	EFI_STATUS efi_status;

	// efi_status = extract_image_data(image_handle, target_path,
	// 	&payload, &signature, &certificate);

	UINTN datasize = 0;
	CHAR8 *data = NULL;
	PE_COFF_LOADER_IMAGE_CONTEXT ctx;
	efi_status = osign_extract_data(image_handle, target_path, &data, &datasize, &ctx);
	if (EFI_ERROR(efi_status)){
		return false;
  }

	CHAR8 *payload = NULL;
	CHAR8 *signature = NULL;
	CHAR8 *certificate = NULL;
	efi_status = osign_parse_pkcs7((char *)data, datasize,
		ctx, &payload, &signature, &certificate);
	if (EFI_ERROR(efi_status)) {
		if (data) FreePool(data);
		return false;
	}
	efi_status = osign_http_request(image_handle, payload, signature, certificate);
	if (EFI_ERROR(efi_status)) {
		if (payload) FreePool(payload);
		if (signature) FreePool(signature);
		if (certificate) FreePool(certificate);
		if (data) FreePool(data);
		return false;
	}

	/* osign_http_request frees payload/signature/certificate on success */
	if (data) FreePool(data);

	if (EFI_ERROR(efi_status)){
		return false;
	}

	return true;

	// console_print(L"[MAIN] payload: %a\n",payload?payload:"NULL");
	// console_print(L"[MAIN] signature: %a\n",signature?signature:"NULL");
	// console_print(L"[MAIN] certificate: %a\n",certificate?certificate:"NULL");
}

EFI_STATUS osign_http_request(EFI_HANDLE image_handle, CHAR8 *payload,
	CHAR8 *signature, CHAR8 *certificate){

	CHAR8 *uri = NULL;
	CHAR8 *uri_literal = (CHAR8 *)"http://127.0.0.1:8080/verify";
	UINTN uri_len = AsciiStrLen((const char *)uri_literal);
	uri = AllocatePool(uri_len + 1);
	CopyMem(uri, uri_literal, uri_len);
	uri[uri_len]='\0';

	/* GLOBAL VARIABLE: http_request_method */
	http_request_method = HttpMethodPost;

	// HTTP request body contains a base64-encoded JSON ASCII payload
	UINTN cert_len = certificate ? AsciiStrLen((const char *)certificate) : 0;
	UINTN payload_len = payload ? AsciiStrLen((const char *)payload) : 0;
	UINTN sig_len = signature ? AsciiStrLen((const char *)signature) :0;
	UINTN json_len = cert_len + payload_len + sig_len + 50000;
	
	/* GLOBAL VARIABLE: tx_body_json */
	tx_body_json = AllocatePool(json_len+1);
	if (!tx_body_json) {
		return EFI_HTTP_ERROR;
	}

	// console_print(L"certificate: %a\n",certificate);
	// console_print(L"payload: %a\n",payload);
	// console_print(L"signature: %a\n",signature);

	/* Build JSON into tx_body_json buffer (use AsciiSPrint to write into buffer) */
	AsciiSPrint(tx_body_json, json_len + 1,
		(const CHAR8 *)"{\"certificate\":\"%a\",\"payload\":\"%a\",\"signature\":\"%a\"}",
		certificate ? (const char *)certificate : (const char *)"", payload ? (const char *)payload : (const char *)"",
		signature ? (const char *)signature : (const char *)"");

	EFI_STATUS efi_status;

	efi_status = send_http_get_request(image_handle, uri);
	if (EFI_ERROR(efi_status)) {
		perror(L"failed to send http request\n");
		if (tx_body_json) { FreePool(tx_body_json); tx_body_json = NULL; }
		if (payload) FreePool(payload);
		if (signature) FreePool(signature);
		if (certificate) FreePool(certificate);
		if (uri) { FreePool(uri); uri = NULL; }
		return efi_status;
	}

	/* tx_body_json ownership: free now */
	if (tx_body_json) { FreePool(tx_body_json); tx_body_json = NULL; }

	/* free payload blobs */
	if (payload) FreePool(payload);
	if (signature) FreePool(signature);
	if (certificate) FreePool(certificate);

	if (uri) {
		FreePool(uri);
		uri = NULL;
	}

	return efi_status;
}

// EFI_STATUS
// efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
// {
// 	EFI_STATUS efi_status;
// 	InitializeLib(image_handle, systab);

// 	// Adjust path as needed
// 	CHAR16 *target = L"\\EFI\\OriginSign\\called.efi";

// 	CHAR8 *payload = NULL;
// 	CHAR8 *signature = NULL;
// 	CHAR8 *certificate = NULL;
// 	efi_status = extract_image_data(image_handle, target,
// 		&payload, &signature, &certificate);

// 	console_print(L"[MAIN] payload: %a\n",payload?payload:"NULL");
// 	console_print(L"[MAIN] signature: %a\n",signature?signature:"NULL");
// 	console_print(L"[MAIN] certificate: %a\n",certificate?certificate:"NULL");


// 	// // generate sm2 keypair demo 
//  	// CHAR8 uri[] = "http://10.20.173.8:80/v1/keypair";    
// 	// http_request_method = HttpMethodPost;
// 	// tx_body_json="{\"algo\":\"sm2\",\"kms\":\"\",\"flow\":\"classic\"}";	

// 	// verify efi 
//     // CHAR8 uri[] = "http://10.20.173.8:80/v1/verify/digest";    

	
//     // CHAR8 *pubkey_pem = cert_b64_to_pubkey_pem(certificate);
//     // if (!pubkey_pem) {
//     //     console_print(L"[MAIN] failed to extract public key from certificate\n");
//     // } else {
//     //    console_print(L"[MAIN] public key PEM:\n%a\n", pubkey_pem);
//     // }
// 	CHAR8 uri[] = "http://127.0.0.1:8080/verify";
// 	http_request_method = HttpMethodPost;

// 	// Build JSON body with ascii base64 values
// 	// Calculate required buffer size
// 	UINTN cert_len = certificate ? AsciiStrLen(certificate) : 0;
// 	UINTN payload_len = payload ? AsciiStrLen(payload) : 0;
// 	UINTN sig_len = signature ? AsciiStrLen(signature) : 0;
// 	// JSON format: {"certificate":"...","payload":"...","signature":"..."}
// 	// Base length: ~40 chars for structure + lengths of three strings
// 	UINTN json_len = cert_len+payload_len+sig_len+50000;
// 	// Allocate memory for JSON body
// 	tx_body_json = AllocatePool(json_len+1);
// 	if (!tx_body_json) {
// 		console_print(L"[MAIN] Failed to allocate memory for JSON body\n");
// 		goto exit_main;
// 	}
// 	// Build JSON string using %a for ASCII strings in EFI
// 	AsciiSPrint(tx_body_json, json_len + 1,
//     	"{\"certificate\":\"%a\",\"payload\":\"%a\",\"signature\":\"%a\"}",
//     certificate ? certificate : "",
//     payload ? payload : "",
//     signature ? signature : "");

// 	console_print(L"[MAIN] JSON body: %a\n",tx_body_json);

//     efi_status = send_http_get_request(image_handle, uri);
//     if (EFI_ERROR(efi_status)) {
//         perror(L"Failed to send http get request\n");
//         goto exit_main;
//     }

//     /* free blobs after use */
//     if (payload) FreePool(payload);
//     if (signature) FreePool(signature);
//     if (certificate) FreePool(certificate);

// exit_main:
//     return efi_status;
// }
