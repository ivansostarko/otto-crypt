package com.ivansostarko.ottocrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** RFC 5869 HKDF (HMAC-SHA256) */
final class HKDF {
    private static final String HMAC = "HmacSHA256";
    static byte[] extract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(salt != null ? salt : new byte[0], HMAC));
        return mac.doFinal(ikm);
    }
    static byte[] expand(byte[] prk, byte[] info, int len) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(prk, HMAC));
        byte[] out = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        byte counter = 1;
        while (pos < len) {
            mac.reset();
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update(counter);
            t = mac.doFinal();
            int copy = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, out, pos, copy);
            pos += copy;
            counter++;
        }
        Arrays.fill(t, (byte)0);
        return out;
    }
    static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
        byte[] prk = extract(salt, ikm);
        byte[] okm = expand(prk, info, len);
        Arrays.fill(prk, (byte)0);
        return okm;
    }
    static byte[] expandNonce(byte[] nonceKey32, byte[] info, int len) throws Exception {
        // Use nonceKey as IKM and empty salt to produce a deterministic nonce (HKDF-SIV-style).
        byte[] prk = extract(new byte[0], nonceKey32);
        byte[] out = expand(prk, info, len);
        Arrays.fill(prk, (byte)0);
        return out;
    }
    static byte[] be64(long v) {
        return ByteBuffer.allocate(8).putLong(v).array();
    }
}
