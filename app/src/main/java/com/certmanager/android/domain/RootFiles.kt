package com.certmanager.android.domain

/** Captured by the descriptor-based helper, never synthesized from user input. */
data class FileMetadata(val header: String) {
    private val fields get() = header.split('\t')
    val uid get() = fields[3].toInt()
    val gid get() = fields[4].toInt()
    val mode get() = fields[5].toInt()
    val context get() = fields[13]
    init {
        val f = header.split('\t')
        require(f.size == 14 && f[0] == "1") { "Invalid file metadata" }
        f.subList(1, 13).forEach { require(it.toLong() >= 0) }
        require(Regex("[A-Za-z0-9_:,.-]{1,255}").matches(f[13]))
        require(f[3].toInt() in listOf(0, 1000) && f[5].toInt() in 0..511 && (f[5].toInt() and 91) == 0) { "Unsafe file ownership/mode" }
    }
}
object RootFilePolicy {
    private val path = Regex("/data/misc/user/(0|[1-9][0-9]{0,5})/cacerts-added/[0-9a-f]{8}\\.[0-9]{1,4}")
    fun eligible(record: CertificateRecord): Boolean = record.source == CertSource.USER &&
        path.matches(record.locator) && CertificatePaths.userId(record.locator) == record.userId
    fun validate(record: CertificateRecord, users: Set<Int>) {
        require(eligible(record)) { "Only traditional user CA files support Root file-level operations" }
        require(record.userId in users) { "Android user not verified" }
    }
}
data class RootFileSnapshot(val raw: ByteArray, val metadata: FileMetadata)
interface RootCertificateFiles {
    fun authorized(): Boolean
    fun verifiedUsers(): Set<Int>
    fun snapshot(record: CertificateRecord): RootFileSnapshot?
    fun move(backup: Backup)
    fun restore(backup: Backup)
    fun duplicates(fingerprint: String, userId: Int): Boolean
}
/** A backup verified here is verified again inside the privileged helper before any mutation. */
class RootFileCertificateUninstaller(private val files: RootCertificateFiles, private val backups: BackupStore) {
    fun capture(record: CertificateRecord): CertificateRecord {
        check(files.authorized()) { "Root authorization required" }
        RootFilePolicy.validate(record, files.verifiedUsers())
        val snapshot = files.snapshot(record) ?: error("CA file missing or inaccessible")
        val cert = Certificates.parse(snapshot.raw)
        check(Certificates.fingerprint(cert.encoded) == record.fingerprint) { "Certificate fingerprint changed" }
        return record.copy(certificate = cert, raw = snapshot.raw, fileMetadata = snapshot.metadata)
    }
    fun uninstall(record: CertificateRecord) {
        val fresh = capture(record)
        val backup = backups.list().firstOrNull { it.locator == fresh.locator && it.userId == fresh.userId &&
            it.fileMetadata == fresh.fileMetadata && it.fingerprint == fresh.fingerprint && it.raw.contentEquals(fresh.raw) }
            ?: error("No matching verified file metadata backup; prepare again")
        BackupCodec.validate(backups.load(backup.id))
        files.move(backup)
        check(files.snapshot(fresh) == null) { "CA reappeared or removal could not be verified; backup retained" }
    }
}
class RootRestoreTicket internal constructor(val backup: Backup, val expiresAt: Long)
class RootFileCertificateRestorer(private val files: RootCertificateFiles, private val backups: BackupStore) {
    private var pending: RootRestoreTicket? = null
    fun prepare(id: String): RootRestoreTicket {
        check(files.authorized()) { "Root authorization required" }
        val b = backups.load(id); BackupCodec.validate(b)
        require(b.certificate.basicConstraints >= 0) { "Only CA certificates can be restored" }
        require(b.fileMetadata != null) { "Backup has no verified file metadata; use system installer" }
        val r = CertificateRecord(b.certificate, b.raw, b.source, b.userId, b.locator, fileMetadata = b.fileMetadata)
        RootFilePolicy.validate(r, files.verifiedUsers())
        check(files.snapshot(r) == null) { "Restore target already exists; no overwrite allowed" }
        check(!files.duplicates(b.fingerprint, b.userId)) { "Certificate already exists in original profile" }
        return RootRestoreTicket(b, System.currentTimeMillis() + 300_000).also { pending = it }
    }
    fun cancel() { pending = null }
    fun confirmed(ticket: RootRestoreTicket) {
        check(pending === ticket) { "Confirmation stale or already consumed" }; pending = null
        check(System.currentTimeMillis() <= ticket.expiresAt && files.authorized())
        val b = backups.load(ticket.backup.id); BackupCodec.validate(b)
        require(b.certificate.basicConstraints >= 0) { "Only CA certificates can be restored" }
        check(b == ticket.backup || BackupCodec.encode(b).contentEquals(BackupCodec.encode(ticket.backup)))
        val r = CertificateRecord(b.certificate, b.raw, b.source, b.userId, b.locator, fileMetadata = b.fileMetadata)
        RootFilePolicy.validate(r, files.verifiedUsers())
        check(files.snapshot(r) == null) { "Restore target appeared; backup retained" }
        check(!files.duplicates(b.fingerprint, b.userId)) { "Duplicate appeared; backup retained" }
        files.restore(b)
        val restored = files.snapshot(r) ?: error("Restored file not observed; backup retained")
        check(restored.raw.contentEquals(b.raw) && restored.metadata.uid == b.fileMetadata!!.uid &&
            restored.metadata.gid == b.fileMetadata.gid && restored.metadata.mode == b.fileMetadata.mode &&
            restored.metadata.context == b.fileMetadata.context) { "Restore verification failed; backup retained" }
    }
}
