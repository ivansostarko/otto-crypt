#ifndef OTTO_CRYPTO_H
#define OTTO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OTTO_TAG_LEN   16
#define OTTO_NONCE_LEN 12

typedef struct {
    uint8_t* header;
    size_t   header_len;
    uint8_t* cipher_and_tag;
    size_t   cipher_and_tag_len;
} otto_enc_result;

int otto_encrypt_string(const uint8_t* plaintext, size_t plaintext_len,
                        const uint8_t raw_key32[32],
                        otto_enc_result* out);

int otto_decrypt_string(const uint8_t* cipher_and_tag, size_t cat_len,
                        const uint8_t* header, size_t header_len,
                        const uint8_t raw_key32[32],
                        uint8_t** plaintext_out, size_t* plaintext_len);

int otto_encrypt_file(const char* in_path, const char* out_path,
                      const uint8_t raw_key32[32], size_t chunk_bytes);

int otto_decrypt_file(const char* in_path, const char* out_path,
                      const uint8_t raw_key32[32]);

void otto_free(void* p);

int otto_x25519_generate(uint8_t sk[32], uint8_t pk[32]);
int otto_x25519_shared(const uint8_t sk[32], const uint8_t pk[32], uint8_t shared[32]);
int otto_hkdf_session(const uint8_t* shared, size_t shared_len,
                      const uint8_t* salt, size_t salt_len, uint8_t out32[32]);

#ifdef __cplusplus
}
#endif
#endif
