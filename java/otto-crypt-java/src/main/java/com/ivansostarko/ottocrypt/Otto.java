package com.ivansostarko.ottocrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

import static com.ivansostarko.ottocrypt.Utils.*;

public final class Otto {
    public static final int DEFAULT_CHUNK_SIZE = 1 << 20; // 1 MiB

    private Otto() {}

    // === Public API (in-memory message) ===

    public static OttoResult encryptString(byte[] plaintext, byte[] rawKey32) throws Exception {
        check(rawKey32 != null && rawKey32.length == 32, "rawKey32 must be 32 bytes");
        boolean chunked = false;
        byte[] fileSalt = random16();
        byte[] header = buildHeader(fileSalt, chunked);

        DerivedKeys dk = deriveKeys(rawKey32, fileSalt);
        byte[] nonce = deriveChunkNonce(dk.nonceKey, 0);
        byte[] cipher = encryptAesGcm(dk.encKey, nonce, header, plaintext);
        return new OttoResult(header, cipher);
    }

    public static byte[] decryptString(byte[] cipherAndTag, byte[] header, byte[] rawKey32) throws Exception {
        check(rawKey32 != null && rawKey32.length == 32, "rawKey32 must be 32 bytes");
        ParsedHeader ph = parseHeader(header);
        DerivedKeys dk = deriveKeys(rawKey32, ph.fileSalt);
        byte[] nonce = deriveChunkNonce(dk.nonceKey, 0);
        return decryptAesGcm(dk.encKey, nonce, header, cipherAndTag);
    }

    // === Files / streaming ===

    public static void encryptFile(Path input, Path output, byte[] rawKey32, int chunkBytes) throws Exception {
        check(rawKey32 != null && rawKey32.length == 32, "rawKey32 must be 32 bytes");
        byte[] fileSalt = random16();
        byte[] header = buildHeader(fileSalt, true);
        DerivedKeys dk = deriveKeys(rawKey32, fileSalt);

        try (InputStream in = Files.newInputStream(input);
             OutputStream out = Files.newOutputStream(output)) {
            out.write(header);
            byte[] buf = new byte[chunkBytes];
            long counter = 0;
            for (;;) {
                int n = in.read(buf);
                if (n < 0) break;
                if (n == 0) continue;
                byte[] pt = Arrays.copyOf(buf, n);
                byte[] nonce = deriveChunkNonce(dk.nonceKey, counter++);
                byte[] ctTag = encryptAesGcm(dk.encKey, nonce, header, pt);
                int ctLen = ctTag.length - TAG_LEN;
                out.write(u32be(ctLen));
                out.write(ctTag, 0, ctLen);
                out.write(ctTag, ctLen, TAG_LEN);
            }
            out.flush();
        }
    }

    public static void decryptFile(Path input, Path output, byte[] rawKey32) throws Exception {
        check(rawKey32 != null && rawKey32.length == 32, "rawKey32 must be 32 bytes");

        try (InputStream in = Files.newInputStream(input);
             OutputStream out = Files.newOutputStream(output)) {
            byte[] fixed = in.readNBytes(FIXED_HDR_LEN);
            check(fixed.length == FIXED_HDR_LEN, "bad header");
            check(Arrays.equals(Arrays.copyOfRange(fixed, 0, 5), MAGIC), "bad magic");
            check(fixed[5] == ALGO_ID && fixed[6] == KDF_RAW, "algo/kdf mismatch");
            int varLen = beU16(fixed, 9);
            byte[] var = in.readNBytes(varLen);
            check(var.length == varLen, "truncated header");
            byte[] header = ByteBuffer.allocate(FIXED_HDR_LEN + varLen).put(fixed).put(var).array();

            ParsedHeader ph = parseHeader(header);
            DerivedKeys dk = deriveKeys(rawKey32, ph.fileSalt);

            long counter = 0;
            for (;;) {
                byte[] lenb = in.readNBytes(4);
                if (lenb.length == 0) break;
                check(lenb.length == 4, "truncated chunk length");
                int clen = beU32(lenb, 0);
                if (clen == 0) break;
                byte[] ct = in.readNBytes(clen);
                check(ct.length == clen, "truncated ciphertext");
                byte[] tag = in.readNBytes(TAG_LEN);
                check(tag.length == TAG_LEN, "missing tag");

                byte[] nonce = deriveChunkNonce(dk.nonceKey, counter++);
                byte[] cat = ByteBuffer.allocate(ct.length + TAG_LEN).put(ct).put(tag).array();
                byte[] pt = decryptAesGcm(dk.encKey, nonce, header, cat);
                out.write(pt);
            }
            out.flush();
        }
    }

    // === X25519 helpers ===

    public static KeyPair x25519Generate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        kpg.initialize(new NamedParameterSpec("X25519"));
        return kpg.generateKeyPair();
    }
    public static byte[] x25519Shared(PrivateKey mySecret, PublicKey theirPublic) throws Exception {
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("X25519");
        ka.init(mySecret);
        ka.doPhase(theirPublic, true);
        return ka.generateSecret();
    }
    public static byte[] hkdfSession(byte[] shared, byte[] salt) throws Exception {
        return HKDF.derive(shared, salt, "OTTO-P2P-SESSION".getBytes(), 32);
    }

    // === internals ===

    private static byte[] buildHeader(byte[] fileSalt16, boolean chunked) {
        check(fileSalt16.length == FILE_SALT_LEN, "file salt must be 16 bytes");
        ByteBuffer buf = ByteBuffer.allocate(FIXED_HDR_LEN + FILE_SALT_LEN);
        buf.put(MAGIC);
        buf.put(ALGO_ID);
        buf.put(KDF_RAW);
        buf.put(chunked ? FLAG_CHUNKED : (byte)0x00);
        buf.put((byte)0x00);
        buf.put(u16be(FILE_SALT_LEN));
        buf.put(fileSalt16);
        return buf.array();
    }

    private static ParsedHeader parseHeader(byte[] header) {
        check(header != null && header.length >= FIXED_HDR_LEN, "header too short");
        check(Arrays.equals(Arrays.copyOfRange(header, 0, 5), MAGIC), "bad magic");
        check(header[5] == ALGO_ID, "algo mismatch");
        check(header[6] == KDF_RAW, "kdf mismatch");
        int varLen = beU16(header, 9);
        check(header.length == FIXED_HDR_LEN + varLen, "header length mismatch");
        check(varLen >= FILE_SALT_LEN, "missing file salt");
        byte[] fileSalt = Arrays.copyOfRange(header, FIXED_HDR_LEN, FIXED_HDR_LEN + FILE_SALT_LEN);
        boolean chunked = (header[7] & FLAG_CHUNKED) != 0;
        return new ParsedHeader(fileSalt, chunked);
    }

    private static final class ParsedHeader {
        final byte[] fileSalt;
        final boolean chunked;
        ParsedHeader(byte[] salt, boolean chunked) { this.fileSalt = salt; this.chunked = chunked; }
    }

    private static final class DerivedKeys {
        final byte[] encKey;   // 32
        final byte[] nonceKey; // 32
        DerivedKeys(byte[] e, byte[] n) { encKey = e; nonceKey = n; }
    }

    private static DerivedKeys deriveKeys(byte[] rawKey32, byte[] fileSalt) throws Exception {
        byte[] encKey = HKDF.derive(rawKey32, fileSalt, "OTTO-ENC-KEY".getBytes(), 32);
        byte[] nonceKey = HKDF.derive(rawKey32, fileSalt, "OTTO-NONCE-KEY".getBytes(), 32);
        return new DerivedKeys(encKey, nonceKey);
    }

    private static byte[] deriveChunkNonce(byte[] nonceKey32, long counter) throws Exception {
        byte[] info = ByteBuffer.allocate("OTTO-CHUNK-NONCE".length() + 8)
                .put("OTTO-CHUNK-NONCE".getBytes())
                .put(HKDF.be64(counter))
                .array();
        return HKDF.expandNonce(nonceKey32, info, NONCE_LEN);
    }

    private static byte[] encryptAesGcm(byte[] encKey32, byte[] nonce12, byte[] aad, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(encKey32, "AES");
        GCMParameterSpec gcm = new GCMParameterSpec(8 * TAG_LEN, nonce12);
        c.init(Cipher.ENCRYPT_MODE, key, gcm);
        if (aad != null && aad.length > 0) c.updateAAD(aad);
        return c.doFinal(pt);
    }

    private static byte[] decryptAesGcm(byte[] encKey32, byte[] nonce12, byte[] aad, byte[] ctAndTag) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(encKey32, "AES");
        GCMParameterSpec gcm = new GCMParameterSpec(8 * TAG_LEN, nonce12);
        c.init(Cipher.DECRYPT_MODE, key, gcm);
        if (aad != null && aad.length > 0) c.updateAAD(aad);
        return c.doFinal(ctAndTag);
    }
}
