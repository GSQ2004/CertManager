package com.certmanager.android.domain

/** A read failure is not an empty store. Disabled records never enter the user CA inventory. */
data class StoreCoverage(val location: String, val readable: Boolean, val detail: String = "")
data class DisabledRecord(val fingerprint: String?, val userId: Int, val location: String)
data class ModuleFinding(val id: String, val disabled: Boolean, val pendingRemoval: Boolean,
    val scriptHint: Boolean, val certificatePaths: List<String>)
data class DuplicateFinding(val fingerprint: String, val userIds: List<Int>, val locations: List<String>)

data class ScanInventory(
    val currentUserId: Int,
    val observations: List<CertificateRecord>,
    val users: Set<Int>,
    val coverage: List<StoreCoverage>,
    val disabled: List<DisabledRecord> = emptyList(),
    val modules: List<ModuleFinding> = emptyList(),
    val bootMarker: String? = null,
    val scannedAt: Long = System.currentTimeMillis()
) {
    val records: List<CertificateRecord> get() = observations.groupBy { it.key }.values.map { group ->
        val primary = group.lastOrNull { !it.locator.startsWith("keystore:") && !it.locator.startsWith("credential:") } ?: group.first()
        primary.copy(observedByKeyStore = group.any { it.observedByKeyStore }, origins = group.flatMap { it.origins }.distinct(),
            observedByCredentialService = group.any { it.observedByCredentialService })
    }
    val userCertificates get() = records.filter { it.source == CertSource.USER }
    val duplicates: List<DuplicateFinding> get() = userCertificates.groupBy { it.fingerprint }.mapNotNull { (fp, group) ->
        val paths = group.flatMap { it.origins }.distinct()
        val repeated = group.any { record ->
            record.origins.count { !it.startsWith("keystore:") && !it.startsWith("credential:") } > 1 ||
                record.origins.count { it.startsWith("keystore:") } > 1
        }
        if (group.map { it.userId }.distinct().size > 1 || repeated)
            DuplicateFinding(fp, group.map { it.userId }.distinct().sorted(), paths) else null
    }
    fun evidenceReadable(record: CertificateRecord): Boolean = record.origins.all { path ->
        val store = when {
            path.startsWith("keystore:") -> "keystore:${record.userId}"
            path.startsWith("credential:") -> "credential:${record.userId}"
            else -> path.substringBeforeLast('/')
        }
        coverage.any { it.location == store && it.readable } && coverage.none { it.location == path && !it.readable }
    }
}

object ModulePaths {
    const val ROOT = "/data/adb/modules"
    private val idPattern = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")
    private val stores = listOf("system/etc/security/cacerts", "system/system/etc/security/cacerts",
        "system/apex/com.android.conscrypt/cacerts", "apex/com.android.conscrypt/cacerts", "cacerts", "certs", "certificates")
    fun validId(id: String): Boolean = idPattern.matches(id) && !id.contains("..")
    fun root(id: String): String { require(validId(id)); return "$ROOT/$id" }
    fun directories(id: String): List<String> = stores.map { "${root(id)}/$it" }
    fun isDirectory(path: String): Boolean {
        val tail = path.removePrefix("$ROOT/")
        if (tail == path) return false
        val id = tail.substringBefore('/')
        return validId(id) && path in directories(id)
    }
}

data class StoreObservation(val certificate: CertificateRecord? = null, val disabled: DisabledRecord? = null)
object InventoryFiles {
    fun inspect(path: String, raw: ByteArray?, currentUserId: Int): StoreObservation {
        require(CertificatePaths.isCertificate(path)) { "Unapproved certificate location" }
        val directory = path.substringBeforeLast('/')
        val user = CertificatePaths.userId(path) ?: currentUserId
        if (directory.endsWith("cacerts-removed")) {
            val fingerprint = raw?.let { runCatching { Certificates.fingerprint(Certificates.parse(it).encoded) }.getOrNull() }
            return StoreObservation(disabled = DisabledRecord(fingerprint, user, path))
        }
        require(raw != null) { "Certificate bytes unavailable" }
        val source = when {
            directory in CertificatePaths.systemDirectories -> CertSource.SYSTEM
            ModulePaths.isDirectory(directory) -> CertSource.MODULE
            else -> CertSource.USER
        }
        return StoreObservation(certificate = CertificateRecord(Certificates.parse(raw), raw, source,
            if (source == CertSource.MODULE) -1 else user, path))
    }
}
