package com.bioauth.phone_auth_native

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

/** The CTAP2/WebAuthn byte structures emitted by the local passkey store. */
internal object Ctap2Encoder {
    const val ES256 = -7

    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_AT = 0x40

    fun coseKey(publicKey: ECPublicKey): ByteArray {
        val x = unsignedCoordinate(publicKey.w.affineX.toByteArray())
        val y = unsignedCoordinate(publicKey.w.affineY.toByteArray())
        return Cbor().apply {
            // CTAP2 canonical order is the bytewise order of the encoded keys:
            // 01, 03, 20, 21, 22. The protocol CBOR writer cannot be reused:
            // it deliberately has no maps, while COSE_Key requires one.
            map(5)
            int(1); int(2) // kty: EC2
            int(3); int(ES256)
            int(-1); int(1) // crv: P-256
            int(-2); bytes(x)
            int(-3); bytes(y)
        }.take()
    }

    fun registrationAuthenticatorData(
        rpId: String,
        credentialId: ByteArray,
        publicKey: ECPublicKey,
        signCount: UInt = 0u,
    ): ByteArray = ByteArrayOutputStream().apply {
        write(sha256(rpId.toByteArray(Charsets.UTF_8)))
        write(FLAG_UP or FLAG_UV or FLAG_AT)
        write(uint32(signCount))
        write(ByteArray(16)) // Privacy-preserving AAGUID for none attestation.
        require(credentialId.size <= 0xffff) { "credentialId is too long" }
        write(byteArrayOf((credentialId.size ushr 8).toByte(), credentialId.size.toByte()))
        write(credentialId)
        write(coseKey(publicKey))
    }.toByteArray()

    fun assertionAuthenticatorData(rpId: String, signCount: UInt): ByteArray =
        ByteArrayOutputStream().apply {
            write(sha256(rpId.toByteArray(Charsets.UTF_8)))
            write(FLAG_UP or FLAG_UV)
            write(uint32(signCount))
        }.toByteArray()

    fun noneAttestationObject(authenticatorData: ByteArray): ByteArray = Cbor().apply {
        // CTAP2 canonical ordering: encoded key length, then bytewise value.
        map(3)
        text("fmt"); text("none")
        text("attStmt"); map(0)
        text("authData"); bytes(authenticatorData)
    }.take()

    fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun uint32(value: UInt): ByteArray =
        ByteBuffer.allocate(4).putInt(value.toInt()).array()

    private fun unsignedCoordinate(encoded: ByteArray): ByteArray {
        val trimmed = if (encoded.size == 33 && encoded[0] == 0.toByte()) encoded.copyOfRange(1, 33) else encoded
        require(trimmed.size <= 32) { "P-256 coordinate is oversized" }
        return ByteArray(32 - trimmed.size) + trimmed
    }

    private class Cbor {
        private val output = ByteArrayOutputStream()

        fun take(): ByteArray = output.toByteArray()
        fun map(size: Int) = head(5, size.toULong())
        fun bytes(value: ByteArray) { head(2, value.size.toULong()); output.write(value) }
        fun text(value: String) {
            val encoded = value.toByteArray(Charsets.UTF_8)
            head(3, encoded.size.toULong())
            output.write(encoded)
        }
        fun int(value: Int) {
            if (value >= 0) head(0, value.toULong()) else head(1, (-1L - value).toULong())
        }

        private fun head(major: Int, argument: ULong) {
            val prefix = major shl 5
            when {
                argument < 24u -> output.write(prefix or argument.toInt())
                argument <= 0xffu -> { output.write(prefix or 24); output.write(argument.toInt()) }
                argument <= 0xffffu -> {
                    output.write(prefix or 25)
                    output.write(argument.toInt() ushr 8)
                    output.write(argument.toInt())
                }
                argument <= 0xffffffffu -> {
                    output.write(prefix or 26)
                    for (shift in 24 downTo 0 step 8) output.write((argument shr shift).toInt())
                }
                else -> {
                    output.write(prefix or 27)
                    for (shift in 56 downTo 0 step 8) output.write((argument shr shift).toInt())
                }
            }
        }
    }
}
