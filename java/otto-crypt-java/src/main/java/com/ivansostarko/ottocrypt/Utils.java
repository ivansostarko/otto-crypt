package com.ivansostarko.ottocrypt;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

final class Utils {
    static final byte[] MAGIC = new byte[]{'O','T','T','O','1'};
    static final byte ALGO_ID = (byte)0xA1;
    static final byte KDF_RAW = (byte)0x02;
    static final byte FLAG_CHUNKED = (byte)0x01;

    static final int FIXED_HDR_LEN = 11; // 5 magic + 1 algo + 1 kdf + 1 flags + 1 reserved + 2 var-len
    static final int FILE_SALT_LEN = 16;
    static final int TAG_LEN = 16;
    static final int NONCE_LEN = 12;

    static final SecureRandom RNG = new SecureRandom();

    static byte[] random16() {
        byte[] b = new byte[16]; RNG.nextBytes(b); return b;
    }

    static byte[] u16be(int v) {
        return ByteBuffer.allocate(2).putShort((short)(v & 0xffff)).array();
    }
    static byte[] u32be(int v) {
        return ByteBuffer.allocate(4).putInt(v).array();
    }
    static int beU16(byte[] v, int off) {
        return ((v[off] & 0xff) << 8) | (v[off+1] & 0xff);
    }
    static int beU32(byte[] v, int off) {
        return ((v[off] & 0xff) << 24) | ((v[off+1] & 0xff) << 16) | ((v[off+2] & 0xff) << 8) | (v[off+3] & 0xff);
    }

    static void check(boolean cond, String msg) {
        if (!cond) throw new IllegalArgumentException(msg);
    }
}
