package com.certmanager.android.domain

import java.util.UUID

interface TrustGateway {
    fun rootAuthorized(): Boolean
    fun reread(record: CertificateRecord): CertificateRecord?
    fun canUninstall(record: CertificateRecord): Boolean
    fun uninstall(record: CertificateRecord)
    fun installed(fingerprint: String, userId: Int): Boolean
}

class DeleteTicket internal constructor(val token: String, val record: CertificateRecord,
    val backupId: String, val direct: Boolean, val expiresAt: Long)
enum class DeleteResult { REMOVED, SYSTEM_SETTINGS_REQUIRED }

/** Preparation runs before the UI confirmation. Commit rechecks all conditions afterwards. */
class CertificateOperations(private val gateway: TrustGateway, private val backups: BackupStore) {
    private val pending = mutableMapOf<String, DeleteTicket>()
    @Synchronized fun prepareDelete(record: CertificateRecord): DeleteTicket {
        check(gateway.rootAuthorized()) { "Root authorization required" }
        require(record.source == CertSource.USER) { "System certificates are read-only" }
        require(CertificatePaths.validLocator(record)) { "Invalid certificate locator" }
        val fresh = gateway.reread(record) ?: error("Certificate no longer available")
        check(fresh.fingerprint == record.fingerprint) { "Certificate changed" }
        val backup = backups.create(fresh)
        BackupCodec.validate(backups.load(backup.id))
        pending.clear()
        return DeleteTicket(UUID.randomUUID().toString(), fresh, backup.id, gateway.canUninstall(fresh),
            System.currentTimeMillis() + 300_000).also { pending[it.token] = it }
    }
    @Synchronized fun cancel(ticket: DeleteTicket) { pending.remove(ticket.token) }
    @Synchronized fun deleteConfirmed(ticket: DeleteTicket): DeleteResult {
        check(pending.remove(ticket.token) === ticket) { "Confirmation expired or already used" }
        check(System.currentTimeMillis() <= ticket.expiresAt) { "Confirmation expired" }
        check(gateway.rootAuthorized()) { "Root authorization lost; backup retained" }
        require(CertificatePaths.validLocator(ticket.record))
        val backup = backups.load(ticket.backupId)
        check(backup.fingerprint == ticket.record.fingerprint && backup.userId == ticket.record.userId)
        val fresh = gateway.reread(ticket.record) ?: error("Certificate unavailable; backup retained")
        check(fresh.fingerprint == backup.fingerprint && fresh.raw.contentEquals(backup.raw)) { "Certificate changed; backup retained" }
        if (!gateway.canUninstall(fresh)) return DeleteResult.SYSTEM_SETTINGS_REQUIRED
        gateway.uninstall(fresh)
        check(!gateway.installed(fresh.fingerprint, fresh.userId) && gateway.reread(fresh) == null) {
            "Removal could not be verified; backup retained"
        }
        return DeleteResult.REMOVED
    }
    fun prepareRestore(backup: Backup, records: List<CertificateRecord>, currentUserId: Int): ByteArray {
        BackupCodec.validate(backup)
        require(backup.source == CertSource.USER) { "System CA backups are export-only" }
        require(backup.userId == currentUserId) { "Open CertManager in the original Android profile" }
        require(backup.certificate.basicConstraints >= 0) { "Only CA certificates are supported" }
        check(!Certificates.duplicate(records, backup.fingerprint, currentUserId)) { "Certificate already exists" }
        check(!gateway.installed(backup.fingerprint, currentUserId)) { "Certificate already exists" }
        return backup.certificate.encoded
    }
    fun verifyRestore(backup: Backup) {
        BackupCodec.validate(backups.load(backup.id))
        check(gateway.installed(backup.fingerprint, backup.userId)) { "Installation not observed; backup retained" }
    }
}
