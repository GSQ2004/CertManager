package com.certmanager.android.domain

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

const val MAX_CERT_BYTES = 1_048_576

enum class CertSource { USER, SYSTEM, MODULE }
enum class TrustState { ENABLED, DISABLED, UNKNOWN }

data class CertificateRecord(
    val certificate: X509Certificate,
    val raw: ByteArray,
    val source: CertSource,
    val userId: Int,
    val locator: String,
    val trust: TrustState = TrustState.UNKNOWN,
    val observedByKeyStore: Boolean = false,
    val origins: List<String> = listOf(locator),
    val observedByCredentialService: Boolean = false,
    val fileMetadata: FileMetadata? = null
) {
    val fingerprint: String get() = Certificates.fingerprint(certificate.encoded)
    val name: String get() = certificate.subjectX500Principal.name
    val key: String get() = "${source.name}:$userId:$fingerprint"
    val expired: Boolean get() = certificate.notAfter.time < System.currentTimeMillis()
    val valid: Boolean get() = !expired && certificate.notBefore.time <= System.currentTimeMillis()
}

object Certificates {
    private const val PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val PEM_END = "-----END CERTIFICATE-----"

    fun parse(raw: ByteArray): X509Certificate {
        require(raw.isNotEmpty() && raw.size <= MAX_CERT_BYTES) { "Invalid certificate size" }
        val der = if (raw.first() == 0x30.toByte()) raw else {
            val text = raw.toString(Charsets.UTF_8).removePrefix("\uFEFF").trim(' ', '\t', '\r', '\n')
            require(text.startsWith(PEM_BEGIN) && text.endsWith(PEM_END)) {
                "Expected a single PEM certificate"
            }
            val body = text.substring(PEM_BEGIN.length, text.length - PEM_END.length)
            Base64.getDecoder().decode(body.filterNot { it == ' ' || it == '\t' || it == '\r' || it == '\n' })
        }
        require(der.firstOrNull() == 0x30.toByte()) { "Expected DER certificate data" }
        val input = ByteArrayInputStream(der)
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        // Preserve the previously accepted trailing whitespace on binary certificate files.
        require(if (der === raw) input.readBytes().all { it.toInt().toChar().isWhitespace() }
                else input.available() == 0) { "Expected one X.509 certificate" }
        return cert
    }
    fun fingerprint(der: ByteArray): String = digest(der).chunked(2).joinToString(":")
    fun digest(raw: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(raw)
        .joinToString("") { "%02X".format(it.toInt() and 0xff) }
    fun pem(cert: X509Certificate): ByteArray = ("-----BEGIN CERTIFICATE-----\n" +
        Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded) +
        "\n-----END CERTIFICATE-----\n").toByteArray(Charsets.US_ASCII)
    fun duplicate(records: List<CertificateRecord>, fingerprint: String, userId: Int): Boolean =
        records.any { it.userId == userId && it.source == CertSource.USER && it.fingerprint == fingerprint }
}
