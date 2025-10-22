#include "otto/otto.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/evp.h>

using namespace std;

static vector<uint8_t> b64decode(const string& s) {
    vector<uint8_t> out(((s.size()+3)/4)*3);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), (int)s.size());
    if (len < 0) throw runtime_error("b64 decode");
    out.resize(len);
    size_t pad = 0;
    if (!s.empty() && s[s.size()-1] == '=') pad++;
    if (s.size() > 1 && s[s.size()-2] == '=') pad++;
    if (pad) out.resize(len - pad);
    return out;
}
static string b64encode(const vector<uint8_t>& v) {
    string out; out.resize(((v.size()+2)/3)*4);
    int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), v.data(), (int)v.size());
    out.resize(len);
    return out;
}

static array<uint8_t,32> decode_key32(const string& b64) {
    auto v = b64decode(b64);
    if (v.size()!=32) throw runtime_error("expected 32-byte base64 key");
    array<uint8_t,32> k{}; copy(v.begin(), v.end(), k.begin()); return k;
}

static int cmd_text(const string& key_b64, const string& message) {
    auto key = decode_key32(key_b64);
    vector<uint8_t> pt(message.begin(), message.end());
    auto enc = otto::Otto::encrypt_string(pt, key);
    cout << "HEADER_B64=" << b64encode(enc.header) << "\n";
    cout << "CIPHER_B64=" << b64encode(enc.cipher_and_tag) << "\n";
    auto dec = otto::Otto::decrypt_string(enc.cipher_and_tag, enc.header, key);
    cout << "DECRYPTED=" << string(dec.begin(), dec.end()) << "\n";
    return 0;
}

static filesystem::path with_ext(const filesystem::path& p, const string& add) {
    auto stem = p.stem().string();
    auto ext = p.extension().string();
    return p.parent_path() / (stem + ext + add);
}

static int cmd_file(const string& key_b64, const filesystem::path& input,
                    optional<filesystem::path> out_enc,
                    optional<filesystem::path> out_dec,
                    size_t chunk) {
    auto key = decode_key32(key_b64);
    filesystem::path enc = out_enc.value_or(input.string() + ".otto");
    filesystem::path dec = out_dec.value_or(input.string() + ".dec");
    cout << "Encrypting " << input << " -> " << enc << "\n";
    otto::Otto::encrypt_file(input.string(), enc.string(), key, chunk);
    cout << "Decrypting " << enc << " -> " << dec << "\n";
    otto::Otto::decrypt_file(enc.string(), dec.string(), key);
    cout << "Done.\n";
    return 0;
}

static int cmd_batch(const string& key_b64, const filesystem::path& dir,
                     const filesystem::path& out, size_t chunk) {
    auto key = decode_key32(key_b64);
    filesystem::create_directories(out);
    for (auto& entry : filesystem::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto p = entry.path();
        if (p.extension() == ".otto") continue;
        auto rel = filesystem::relative(p, dir);
        auto out_dir = out / rel.parent_path();
        filesystem::create_directories(out_dir);
        auto enc_out = (out_dir / rel.filename()).string() + ".otto";
        auto dec_out = (out_dir / rel.filename()).string() + ".dec";
        cout << "Encrypting " << p << " -> " << enc_out << "\n";
        otto::Otto::encrypt_file(p.string(), enc_out, key, chunk);
        cout << "Decrypting " << enc_out << " -> " << dec_out << "\n";
        otto::Otto::decrypt_file(enc_out, dec_out, key);
    }
    cout << "Batch complete. Output: " << out << "\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cerr << "otto-demo\n"
"USAGE:\n"
"  otto-demo text --key-b64 <key> --message <utf8>\n"
"  otto-demo file --key-b64 <key> --input <path> [--out-enc <path>] [--out-dec <path>] [--chunk <bytes>]\n"
"  otto-demo batch --key-b64 <key> --dir <dir> --out <dir> [--chunk <bytes>]\n";
        return 1;
    }
    string cmd = argv[1];
    try {
        if (cmd == "text") {
            string key, msg; 
            for (int i=2;i<argc;i++) {
                string a = argv[i];
                if (a=="--key-b64" && i+1<argc) key = argv[++i];
                else if (a=="--message" && i+1<argc) msg = argv[++i];
            }
            if (key.empty() || msg.empty()) throw runtime_error("missing --key-b64 or --message");
            return cmd_text(key, msg);
        } else if (cmd == "file") {
            string key; string in; string oenc; string odec; size_t chunk = 1u<<20;
            for (int i=2;i<argc;i++) {
                string a = argv[i];
                if (a=="--key-b64" && i+1<argc) key = argv[++i];
                else if (a=="--input" && i+1<argc) in = argv[++i];
                else if (a=="--out-enc" && i+1<argc) oenc = argv[++i];
                else if (a=="--out-dec" && i+1<argc) odec = argv[++i];
                else if (a=="--chunk" && i+1<argc) chunk = stoull(argv[++i]);
            }
            if (key.empty() || in.empty()) throw runtime_error("missing --key-b64 or --input");
            optional<filesystem::path> pe, pd;
            if (!oenc.empty()) pe = filesystem::path(oenc);
            if (!odec.empty()) pd = filesystem::path(odec);
            return cmd_file(key, filesystem::path(in), pe, pd, chunk);
        } else if (cmd == "batch") {
            string key; string dir; string out; size_t chunk = 1u<<20;
            for (int i=2;i<argc;i++) {
                string a = argv[i];
                if (a=="--key-b64" && i+1<argc) key = argv[++i];
                else if (a=="--dir" && i+1<argc) dir = argv[++i];
                else if (a=="--out" && i+1<argc) out = argv[++i];
                else if (a=="--chunk" && i+1<argc) chunk = stoull(argv[++i]);
            }
            if (key.empty() || dir.empty() || out.empty()) throw runtime_error("missing --key-b64/--dir/--out");
            return cmd_batch(key, filesystem::path(dir), filesystem::path(out), chunk);
        } else {
            throw runtime_error("unknown command");
        }
    } catch (const exception& e) {
        cerr << "ERROR: " << e.what() << "\n";
        return 2;
    }
}
