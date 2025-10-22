#include "otto/otto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static unsigned char* b64decode(const char* s, size_t* outlen) {
    size_t slen = strlen(s);
    unsigned char* out = (unsigned char*)malloc(((slen+3)/4)*3);
    int len = EVP_DecodeBlock(out, (const unsigned char*)s, (int)slen);
    if (len < 0) { free(out); return NULL; }
    size_t pad = 0;
    if (slen && s[slen-1]=='=') pad++;
    if (slen>1 && s[slen-2]=='=') pad++;
    *outlen = (size_t)(len - (int)pad);
    return out;
}

static char* b64encode(const unsigned char* buf, size_t len) {
    char* out = (char*)malloc(((len+2)/3)*4 + 1);
    int l = EVP_EncodeBlock((unsigned char*)out, buf, (int)len);
    out[l] = '\0';
    return out;
}

static void usage(void) {
    fprintf(stderr,
"otto-cli\n"
"USAGE:\n"
"  otto-cli enc-str <b64rawkey32> <utf8_plaintext>\n"
"  otto-cli dec-str <b64rawkey32> <b64header> <b64cipher_and_tag>\n"
"  otto-cli enc-file <b64rawkey32> <in> <out> [chunk_bytes]\n"
"  otto-cli dec-file <b64rawkey32> <in> <out>\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* cmd = argv[1];
    if (strcmp(cmd, "enc-str") == 0) {
        if (argc < 4) { usage(); return 1; }
        size_t klen=0; unsigned char* k = b64decode(argv[2], &klen);
        if (!k || klen != 32) { fprintf(stderr, "bad key\n"); free(k); return 2; }
        const char* msg = argv[3];
        otto_enc_result res = {0};
        if (otto_encrypt_string((const uint8_t*)msg, strlen(msg), k, &res) != 0) {
            fprintf(stderr, "encrypt failed\n"); free(k); return 2;
        }
        char* hb64 = b64encode(res.header, res.header_len);
        char* cb64 = b64encode(res.cipher_and_tag, res.cipher_and_tag_len);
        printf("HEADER_B64=%s\n", hb64);
        printf("CIPHER_B64=%s\n", cb64);
        free(hb64); free(cb64);
        otto_free(res.header); otto_free(res.cipher_and_tag);
        free(k);
        return 0;
    } else if (strcmp(cmd, "dec-str") == 0) {
        if (argc < 5) { usage(); return 1; }
        size_t klen=0, hlen=0, clen=0;
        unsigned char* k = b64decode(argv[2], &klen);
        unsigned char* h = b64decode(argv[3], &hlen);
        unsigned char* c = b64decode(argv[4], &clen);
        if (!k || klen!=32 || !h || !c) { fprintf(stderr, "bad inputs\n"); free(k); free(h); free(c); return 2; }
        uint8_t* pt=NULL; size_t ptlen=0;
        if (otto_decrypt_string(c, clen, h, hlen, k, &pt, &ptlen) != 0) {
            fprintf(stderr, "decrypt failed\n"); free(k); free(h); free(c); return 2;
        }
        fwrite(pt, 1, ptlen, stdout); fputc('\n', stdout);
        otto_free(pt); free(k); free(h); free(c);
        return 0;
    } else if (strcmp(cmd, "enc-file") == 0) {
        if (argc < 5) { usage(); return 1; }
        size_t klen=0; unsigned char* k = b64decode(argv[2], &klen);
        if (!k || klen!=32) { fprintf(stderr, "bad key\n"); free(k); return 2; }
        size_t chunk = (argc>=6) ? (size_t)strtoull(argv[5], NULL, 10) : (1u<<20);
        if (otto_encrypt_file(argv[3], argv[4], k, chunk) != 0) {
            fprintf(stderr, "enc-file failed\n"); free(k); return 2;
        }
        printf("OK\n"); free(k); return 0;
    } else if (strcmp(cmd, "dec-file") == 0) {
        if (argc < 5) { usage(); return 1; }
        size_t klen=0; unsigned char* k = b64decode(argv[2], &klen);
        if (!k || klen!=32) { fprintf(stderr, "bad key\n"); free(k); return 2; }
        if (otto_decrypt_file(argv[3], argv[4], k) != 0) {
            fprintf(stderr, "dec-file failed\n"); free(k); return 2;
        }
        printf("OK\n"); free(k); return 0;
    } else {
        usage(); return 1;
    }
}
