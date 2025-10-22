#include "otto/otto.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const uint8_t MAGIC[5] = {'O','T','T','O','1'};
static const uint8_t ALGO_ID = 0xA1;
static const uint8_t KDF_RAW = 0x02;
static const uint8_t FLAG_CHUNKED = 0x01;
static const size_t  FIXED_HDR = 11;
static const size_t  FILE_SALT = 16;

static int hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                       const uint8_t* salt, size_t salt_len,
                       const uint8_t* info, size_t info_len,
                       uint8_t* out, size_t out_len) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    int ok = 0;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto done;
    if (info && info_len) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto done;
    }
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out, &len) <= 0 || len != out_len) goto done;
    ok = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    return ok ? 0 : -1;
}

static int hkdf_nonce12(const uint8_t nonce_key[32], const uint8_t* info, size_t info_len,
                        uint8_t out_nonce12[OTTO_NONCE_LEN]) {
    return hkdf_sha256(nonce_key, 32, NULL, 0, info, info_len, out_nonce12, OTTO_NONCE_LEN);
}

static void u16be(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)(v); }
static void u32be(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static uint32_t be32(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3]; }

static int build_header(uint8_t* header, size_t* header_len,
                        const uint8_t file_salt[FILE_SALT], int chunked) {
    size_t need = FIXED_HDR + FILE_SALT;
    if (*header_len < need) { *header_len = need; return -1; }
    uint8_t* p = header;
    memcpy(p, MAGIC, 5); p += 5;
    *p++ = ALGO_ID;
    *p++ = KDF_RAW;
    *p++ = chunked ? FLAG_CHUNKED : 0x00;
    *p++ = 0x00;
    u16be(p, (uint16_t)FILE_SALT); p += 2;
    memcpy(p, file_salt, FILE_SALT); p += FILE_SALT;
    *header_len = (size_t)(p - header);
    return 0;
}

static int parse_header(const uint8_t* header, size_t header_len,
                        uint8_t file_salt_out[FILE_SALT], int* chunked_flag) {
    if (header_len < FIXED_HDR) return -1;
    if (memcmp(header, MAGIC, 5) != 0) return -1;
    if (header[5] != ALGO_ID || header[6] != KDF_RAW) return -1;
    *chunked_flag = (header[7] & FLAG_CHUNKED) ? 1 : 0;
    uint16_t var_len = ((uint16_t)header[9] << 8) | header[10];
    if (header_len != FIXED_HDR + var_len) return -1;
    if (var_len < FILE_SALT) return -1;
    memcpy(file_salt_out, header + FIXED_HDR, FILE_SALT);
    return 0;
}

static int derive_keys(const uint8_t raw_key32[32], const uint8_t file_salt[FILE_SALT],
                       uint8_t enc_key[32], uint8_t nonce_key[32]) {
    static const uint8_t info_enc[] = "OTTO-ENC-KEY";
    static const uint8_t info_nonc[] = "OTTO-NONCE-KEY";
    if (hkdf_sha256(raw_key32, 32, file_salt, FILE_SALT, info_enc, sizeof(info_enc)-1, enc_key, 32) != 0) return -1;
    if (hkdf_sha256(raw_key32, 32, file_salt, FILE_SALT, info_nonc, sizeof(info_nonc)-1, nonce_key, 32) != 0) return -1;
    return 0;
}

static int chunk_nonce(const uint8_t nonce_key[32], uint64_t counter, uint8_t out_nonce[OTTO_NONCE_LEN]) {
    uint8_t info[sizeof("OTTO-CHUNK-NONCE")-1 + 8];
    memcpy(info, "OTTO-CHUNK-NONCE", sizeof("OTTO-CHUNK-NONCE")-1);
    uint8_t* ctr = info + (sizeof("OTTO-CHUNK-NONCE")-1);
    for (int i = 7; i >= 0; --i) { ctr[i] = (uint8_t)(counter & 0xff); counter >>= 8; }
    return hkdf_nonce12(nonce_key, info, sizeof(info), out_nonce);
}

static int aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[OTTO_NONCE_LEN],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt, size_t pt_len,
                           uint8_t* ct_out, uint8_t tag_out[OTTO_TAG_LEN]) {
    int ok = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len=0, outlen=0;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, OTTO_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad && aad_len) { if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done; }
    if (EVP_EncryptUpdate(ctx, ct_out, &outlen, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct_out + outlen, &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, OTTO_TAG_LEN, tag_out) != 1) goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[OTTO_NONCE_LEN],
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct, size_t ct_len,
                           const uint8_t tag[OTTO_TAG_LEN],
                           uint8_t* pt_out) {
    int ok = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len=0, outlen=0;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, OTTO_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad && aad_len) { if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done; }
    if (EVP_DecryptUpdate(ctx, pt_out, &outlen, ct, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, OTTO_TAG_LEN, (void*)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt_out + outlen, &len) != 1) goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Public API */

void otto_free(void* p) { free(p); }

int otto_encrypt_string(const uint8_t* plaintext, size_t plaintext_len,
                        const uint8_t raw_key32[32], otto_enc_result* out) {
    int rc = -1;
    uint8_t file_salt[FILE_SALT];
    uint8_t enc_key[32], nonce_key[32], nonce[OTTO_NONCE_LEN], tag[OTTO_TAG_LEN];
    uint8_t* header = NULL; uint8_t* cat = NULL;
    if (!plaintext || !out || !raw_key32) return -1;
    if (RAND_bytes(file_salt, (int)sizeof(file_salt)) != 1) return -1;
    size_t header_len = FIXED_HDR + FILE_SALT;
    header = (uint8_t*)malloc(header_len);
    if (!header) goto done;
    if (build_header(header, &header_len, file_salt, 0) != 0) goto done;
    if (derive_keys(raw_key32, file_salt, enc_key, nonce_key) != 0) goto done;
    if (chunk_nonce(nonce_key, 0, nonce) != 0) goto done;
    cat = (uint8_t*)malloc(plaintext_len + OTTO_TAG_LEN);
    if (!cat) goto done;
    if (aes_gcm_encrypt(enc_key, nonce, header, header_len, plaintext, plaintext_len, cat, tag) != 0) goto done;
    memcpy(cat + plaintext_len, tag, OTTO_TAG_LEN);
    out->header = header; out->header_len = header_len;
    out->cipher_and_tag = cat; out->cipher_and_tag_len = plaintext_len + OTTO_TAG_LEN;
    rc = 0; header = NULL; cat = NULL;
done:
    if (header) free(header);
    if (cat) free(cat);
    return rc;
}

int otto_decrypt_string(const uint8_t* cipher_and_tag, size_t cat_len,
                        const uint8_t* header, size_t header_len,
                        const uint8_t raw_key32[32],
                        uint8_t** plaintext_out, size_t* plaintext_len) {
    uint8_t file_salt[FILE_SALT]; int chunked = 0;
    uint8_t enc_key[32], nonce_key[32], nonce[OTTO_NONCE_LEN], tag[OTTO_TAG_LEN];
    if (!cipher_and_tag || !header || !plaintext_out || !plaintext_len) return -1;
    if (cat_len < OTTO_TAG_LEN) return -1;
    if (parse_header(header, header_len, file_salt, &chunked) != 0) return -1;
    if (derive_keys(raw_key32, file_salt, enc_key, nonce_key) != 0) return -1;
    if (chunk_nonce(nonce_key, 0, nonce) != 0) return -1;
    size_t ct_len = cat_len - OTTO_TAG_LEN;
    memcpy(tag, cipher_and_tag + ct_len, OTTO_TAG_LEN);
    uint8_t* pt = (uint8_t*)malloc(ct_len);
    if (!pt) return -1;
    if (aes_gcm_decrypt(enc_key, nonce, header, header_len, cipher_and_tag, ct_len, tag, pt) != 0) {
        free(pt); return -1;
    }
    *plaintext_out = pt; *plaintext_len = ct_len;
    return 0;
}

int otto_encrypt_file(const char* in_path, const char* out_path,
                      const uint8_t raw_key32[32], size_t chunk_bytes) {
    if (!in_path || !out_path || !raw_key32) return -1;
    if (chunk_bytes == 0) chunk_bytes = 1u<<20;
    FILE* fi = fopen(in_path, "rb"); if (!fi) return -1;
    FILE* fo = fopen(out_path, "wb"); if (!fo) { fclose(fi); return -1; }
    uint8_t file_salt[FILE_SALT]; if (RAND_bytes(file_salt, (int)sizeof(file_salt)) != 1) { fclose(fi); fclose(fo); return -1; }
    size_t header_len = FIXED_HDR + FILE_SALT;
    uint8_t* header = (uint8_t*)malloc(header_len);
    if (!header) { fclose(fi); fclose(fo); return -1; }
    if (build_header(header, &header_len, file_salt, 1) != 0) { free(header); fclose(fi); fclose(fo); return -1; }
    uint8_t enc_key[32], nonce_key[32]; if (derive_keys(raw_key32, file_salt, enc_key, nonce_key) != 0) { free(header); fclose(fi); fclose(fo); return -1; }
    fwrite(header, 1, header_len, fo);
    uint8_t* buf = (uint8_t*)malloc(chunk_bytes);
    uint8_t* ct  = (uint8_t*)malloc(chunk_bytes);
    uint8_t tag[OTTO_TAG_LEN], nonce[OTTO_NONCE_LEN];
    uint64_t counter = 0;
    while (1) {
        size_t n = fread(buf, 1, chunk_bytes, fi);
        if (n == 0) { if (feof(fi)) break; else { free(buf); free(ct); free(header); fclose(fi); fclose(fo); return -1; } }
        if (chunk_nonce(nonce_key, counter++, nonce) != 0) { free(buf); free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        if (aes_gcm_encrypt(enc_key, nonce, header, header_len, buf, n, ct, tag) != 0) { free(buf); free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        uint8_t lenb[4]; u32be(lenb, (uint32_t)n);
        fwrite(lenb, 1, 4, fo); fwrite(ct, 1, n, fo); fwrite(tag, 1, OTTO_TAG_LEN, fo);
    }
    free(buf); free(ct); free(header); fclose(fi); fclose(fo); return 0;
}

int otto_decrypt_file(const char* in_path, const char* out_path,
                      const uint8_t raw_key32[32]) {
    if (!in_path || !out_path || !raw_key32) return -1;
    FILE* fi = fopen(in_path, "rb"); if (!fi) return -1;
    uint8_t fixed[FIXED_HDR];
    if (fread(fixed, 1, FIXED_HDR, fi) != FIXED_HDR) { fclose(fi); return -1; }
    if (memcmp(fixed, MAGIC, 5) != 0) { fclose(fi); return -1; }
    if (fixed[5] != ALGO_ID || fixed[6] != KDF_RAW) { fclose(fi); return -1; }
    uint16_t varlen = ((uint16_t)fixed[9] << 8) | fixed[10];
    uint8_t* var = (uint8_t*)malloc(varlen); if (!var) { fclose(fi); return -1; }
    if (fread(var, 1, varlen, fi) != varlen) { free(var); fclose(fi); return -1; }
    size_t header_len = FIXED_HDR + varlen;
    uint8_t* header = (uint8_t*)malloc(header_len); if (!header) { free(var); fclose(fi); return -1; }
    memcpy(header, fixed, FIXED_HDR); memcpy(header + FIXED_HDR, var, varlen); free(var);
    uint8_t file_salt[FILE_SALT]; int chunked = 0;
    if (parse_header(header, header_len, file_salt, &chunked) != 0) { free(header); fclose(fi); return -1; }
    uint8_t enc_key[32], nonce_key[32];
    if (derive_keys(raw_key32, file_salt, enc_key, nonce_key) != 0) { free(header); fclose(fi); return -1; }
    FILE* fo = fopen(out_path, "wb"); if (!fo) { free(header); fclose(fi); return -1; }
    uint64_t counter = 0; uint8_t nonce[OTTO_NONCE_LEN], tag[OTTO_TAG_LEN];
    while (1) {
        uint8_t lenb[4];
        size_t r = fread(lenb, 1, 4, fi);
        if (r == 0) break;
        if (r != 4) { free(header); fclose(fi); fclose(fo); return -1; }
        uint32_t clen = be32(lenb);
        if (clen == 0) break;
        uint8_t* ct = (uint8_t*)malloc(clen);
        if (!ct) { free(header); fclose(fi); fclose(fo); return -1; }
        if (fread(ct, 1, clen, fi) != clen) { free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        if (fread(tag, 1, OTTO_TAG_LEN, fi) != OTTO_TAG_LEN) { free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        if (chunk_nonce(nonce_key, counter++, nonce) != 0) { free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        uint8_t* pt = (uint8_t*)malloc(clen);
        if (!pt) { free(ct); free(header); fclose(fi); fclose(fo); return -1; }
        if (aes_gcm_decrypt(enc_key, nonce, header, header_len, ct, clen, tag, pt) != 0) {
            free(pt); free(ct); free(header); fclose(fi); fclose(fo); return -1;
        }
        fwrite(pt, 1, clen, fo);
        free(pt); free(ct);
    }
    free(header); fclose(fi); fclose(fo); return 0;
}

int otto_x25519_generate(uint8_t sk[32], uint8_t pk[32]) {
    int rc = -1;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx) return -1;
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto done;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto done;
    size_t sklen = 32, pklen = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &sklen) <= 0 || sklen != 32) goto done;
    if (EVP_PKEY_get_raw_public_key (pkey, pk, &pklen) <= 0 || pklen != 32) goto done;
    rc = 0;
done:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return rc;
}

int otto_x25519_shared(const uint8_t sk[32], const uint8_t pk[32], uint8_t shared[32]) {
    int rc = -1;
    EVP_PKEY* pvt = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, NULL, pk, 32);
    if (!pvt || !pub) { EVP_PKEY_free(pvt); EVP_PKEY_free(pub); return -1; }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pvt, NULL);
    if (!ctx) { EVP_PKEY_free(pvt); EVP_PKEY_free(pub); return -1; }
    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) goto done;
    size_t outlen = 32;
    if (EVP_PKEY_derive(ctx, shared, &outlen) <= 0 || outlen != 32) goto done;
    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pvt); EVP_PKEY_free(pub);
    return rc;
}

int otto_hkdf_session(const uint8_t* shared, size_t shared_len,
                      const uint8_t* salt, size_t salt_len, uint8_t out32[32]) {
    static const uint8_t info[] = "OTTO-P2P-SESSION";
    return hkdf_sha256(shared, shared_len, salt, salt_len, info, sizeof(info)-1, out32, 32);
}
