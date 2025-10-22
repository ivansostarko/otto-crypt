#include "otto/otto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
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

static void usage(void) {
    fprintf(stderr,
"otto-demo (C)\n"
"USAGE:\n"
"  text  --key-b64 <key> --message <utf8>\n"
"  file  --key-b64 <key> --input <path> [--out-enc <path>] [--out-dec <path>] [--chunk <bytes>]\n"
"  batch --key-b64 <key> --dir <dir> --out <dir> [--chunk <bytes>]\n");
}

static const char* opt(char** argv, int argc, const char* name) {
    for (int i=0;i<argc-1;i++) if (strcmp(argv[i], name)==0) return argv[i+1];
    return NULL;
}

static int ensure_dir(const char* path) {
#ifdef _WIN32
    struct _stat st;
    if (_stat(path, &st) == 0 && (st.st_mode & _S_IFDIR)) return 0;
    return _mkdir(path);
#else
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    return mkdir(path, 0775);
#endif
}

static int process_file(const char* in, const char* outDir, const uint8_t* key, size_t chunk) {
    char outEnc[4096]; snprintf(outEnc, sizeof(outEnc), "%s/%s.otto", outDir, strrchr(in,'/')?strrchr(in,'/')+1:in);
    char outDec[4096]; snprintf(outDec, sizeof(outDec), "%s/%s.dec",  outDir, strrchr(in,'/')?strrchr(in,'/')+1:in);
    printf("Encrypting %s -> %s\n", in, outEnc);
    if (otto_encrypt_file(in, outEnc, key, chunk) != 0) { fprintf(stderr, "enc failed\n"); return -1; }
    printf("Decrypting %s -> %s\n", outEnc, outDec);
    if (otto_decrypt_file(outEnc, outDec, key) != 0) { fprintf(stderr, "dec failed\n"); return -1; }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* cmd = argv[1];
    if (strcmp(cmd, "text") == 0) {
        const char* keyb64 = opt(argv, argc, "--key-b64");
        const char* msg = opt(argv, argc, "--message");
        if (!keyb64 || !msg) { usage(); return 2; }
        size_t klen=0; unsigned char* key = b64decode(keyb64, &klen);
        if (!key || klen!=32) { fprintf(stderr, "bad key\n"); free(key); return 2; }
        otto_enc_result res = {0};
        if (otto_encrypt_string((const uint8_t*)msg, strlen(msg), key, &res) != 0) { fprintf(stderr, "encrypt failed\n"); free(key); return 3; }
        printf("HEADER_B64=%.*s\n", (int)((res.header_len+2)/3*4), ""); /* placeholder; use otto-cli for b64 */
        printf("CIPHER_AND_TAG_LEN=%zu\n", res.cipher_and_tag_len);
        uint8_t* pt=NULL; size_t ptlen=0;
        if (otto_decrypt_string(res.cipher_and_tag, res.cipher_and_tag_len, res.header, res.header_len, key, &pt, &ptlen) != 0) {
            fprintf(stderr, "decrypt failed\n"); otto_free(res.header); otto_free(res.cipher_and_tag); free(key); return 3;
        }
        printf("DECRYPTED=%.*s\n", (int)ptlen, pt);
        otto_free(pt); otto_free(res.header); otto_free(res.cipher_and_tag); free(key);
        return 0;
    } else if (strcmp(cmd, "file") == 0) {
        const char* keyb64 = opt(argv, argc, "--key-b64");
        const char* in = opt(argv, argc, "--input");
        const char* outEnc = opt(argv, argc, "--out-enc");
        const char* outDec = opt(argv, argc, "--out-dec");
        const char* chunkStr = opt(argv, argc, "--chunk");
        if (!keyb64 || !in) { usage(); return 2; }
        size_t klen=0; unsigned char* key = b64decode(keyb64, &klen);
        if (!key || klen!=32) { fprintf(stderr, "bad key\n"); free(key); return 2; }
        size_t chunk = chunkStr ? (size_t)strtoull(chunkStr,NULL,10) : (1u<<20);
        char encbuf[4096], decbuf[4096];
        snprintf(encbuf, sizeof(encbuf), "%s", outEnc ? outEnc : "out.otto");
        snprintf(decbuf, sizeof(decbuf), "%s", outDec ? outDec : "out.dec");
        if (otto_encrypt_file(in, encbuf, key, chunk) != 0) { fprintf(stderr, "enc-file failed\n"); free(key); return 3; }
        if (otto_decrypt_file(encbuf, decbuf, key) != 0) { fprintf(stderr, "dec-file failed\n"); free(key); return 3; }
        printf("OK: %s -> %s -> %s\n", in, encbuf, decbuf);
        free(key); return 0;
    } else if (strcmp(cmd, "batch") == 0) {
        const char* keyb64 = opt(argv, argc, "--key-b64");
        const char* dir = opt(argv, argc, "--dir");
        const char* out = opt(argv, argc, "--out");
        const char* chunkStr = opt(argv, argc, "--chunk");
        if (!keyb64 || !dir || !out) { usage(); return 2; }
        size_t klen=0; unsigned char* key = b64decode(keyb64, &klen);
        if (!key || klen!=32) { fprintf(stderr, "bad key\n"); free(key); return 2; }
        size_t chunk = chunkStr ? (size_t)strtoull(chunkStr,NULL,10) : (1u<<20);
        ensure_dir(out);
        DIR* d = opendir(dir);
        if (!d) { fprintf(stderr, "cannot open dir\n"); free(key); return 3; }
        struct dirent* e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name,".")==0 || strcmp(e->d_name,"..")==0) continue;
            char path[4096]; snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            struct stat st;
            if (stat(path, &st) != 0) continue;
            if (S_ISREG(st.st_mode)) {
                if (process_file(path, out, key, chunk) != 0) { closedir(d); free(key); return 4; }
            }
        }
        closedir(d); free(key);
        printf("Batch done\n"); return 0;
    } else {
        usage(); return 1;
    }
}
