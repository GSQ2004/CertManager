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
    val observedByCredentialService: Boolean = false
) {
    val fingerprint: String get() = Certificates.fingerprint(certificate.encoded)
    val name: String get() = certificate.subjectX500Principal.name
    val key: String get() = "${source.name}:$userId:$fingerprint"
    val expired: Boolean get() = certificate.notAfter.time < System.currentTimeMillis()
    val valid: Boolean get() = !expired && certificate.notBefore.time <= System.currentTimeMillis()
}

object Certificates {
    fun parse(raw: ByteArray): X509Certificate {
        require(raw.isNotEmpty() && raw.size <= MAX_CERT_BYTES) { "Invalid certificate size" }
        if (raw.first() == '-'.code.toByte()) {
            val text = raw.toString(Charsets.US_ASCII).trim()
            require(text.startsWith("-----BEGIN CERTIFICATE-----") && text.endsWith("-----END CERTIFICATE-----") &&
                "-----BEGIN CERTIFICATE-----".toRegex().findAll(text).count() == 1 && !text.contains("PRIVATE KEY")) {
                "Expected a single PEM certificate"
            }
        }
        // A single certificate only; private keys and certificate bundles are never imported.
        val input = ByteArrayInputStream(raw)
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        require(input.readBytes().all { it.toInt().toChar().isWhitespace() }) { "Expected one X.509 certificate" }
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
