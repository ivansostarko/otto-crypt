package com.ivansostarko.ottocrypt;

public final class OttoResult {
    public final byte[] header;          // AAD header
    public final byte[] cipherAndTag;    // ciphertext || tag[16]

    public OttoResult(byte[] header, byte[] cipherAndTag) {
        this.header = header;
        this.cipherAndTag = cipherAndTag;
    }
}
