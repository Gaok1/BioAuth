package com.bioauth.phone_auth_native

import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

internal class Ctap2EncoderTest {
    private val publicKey: ECPublicKey by lazy {
        val parameters = java.security.AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(
                ECPoint(
                    BigInteger("afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61", 16),
                    BigInteger("930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220", 16),
                ),
                parameters,
            ),
        ) as ECPublicKey
    }

    @Test
    fun coseKeyMatchesTheWebAuthnLevel3FixedVector() {
        assertEquals(
            "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
            Ctap2Encoder.coseKey(publicKey).hex(),
        )
    }

    @Test
    fun authenticatorDataMatchesTheWebAuthnLevel3FixedVector() {
        val credentialId = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4".bytes()
        val actual = Ctap2Encoder.registrationAuthenticatorData("example.org", credentialId, publicKey)

        assertEquals(
            "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5" +
                "45" + "00000000" + "00000000000000000000000000000000" + "0020" +
                "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" +
                "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
            actual.hex(),
        )
        assertEquals(0x45, actual[32].toInt() and 0xff)
    }

    @Test
    fun noneAttestationUsesCanonicalMapOrdering() {
        assertEquals(
            "a363666d74646e6f6e656761747453746d74a068617574684461746143010203",
            Ctap2Encoder.noneAttestationObject(byteArrayOf(1, 2, 3)).hex(),
        )
    }

    @Test
    fun assertionDataCarriesAnUnsignedBigEndianCounter() {
        val data = Ctap2Encoder.assertionAuthenticatorData("example.org", 0x80000001u)
        assertContentEquals(byteArrayOf(0x80.toByte(), 0, 0, 1), data.copyOfRange(33, 37))
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun String.bytes() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
