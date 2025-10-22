package com.ivansostarko.ottocrypt.android

data class OttoResult(
    val header: ByteArray,
    val cipherAndTag: ByteArray
)
