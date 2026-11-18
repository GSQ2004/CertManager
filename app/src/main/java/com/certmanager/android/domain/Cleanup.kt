package com.certmanager.android.domain

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties
import java.util.UUID

interface CleanupGateway : TrustGateway {
    fun scanInventory(): ScanInventory
    fun uninstallBlockReason(record: CertificateRecord): String
}

enum class CleanupStatus { PENDING, REMOVED, FILE_MOVED, SKIPPED, FAILED, UNVERIFIED }
data class CleanupEntry(val key: String, val fingerprint: String, val userId: Int,
    val backupIds: List<String>, val status: CleanupStatus, val reason: String,
    val backupVerified: Boolean = true, val fileMoved: Boolean = false, val activeRechecked: Boolean = false, val rebootRechecked: Boolean = false, val movedFiles: Int = 0)
data class CleanupHistory(val bootMarker: String?, val createdAt: Long,
    val entries: List<CleanupEntry>, val systemFingerprints: Set<String>, val warningGoneConfirmed: Boolean = false)
data class CleanupReview(val remaining: Int, val targetedRemaining: List<String>, val reappeared: List<String>,
    val possibleInjection: List<String>, val rebootDetected: Boolean?, val duplicates: List<DuplicateFinding>)
data class CleanupReport(val history: CleanupHistory, val inventory: ScanInventory, val review: CleanupReview)
data class CapturedCa(val record: CertificateRecord, val backupId: String)
data class CleanupTarget(val record: CertificateRecord, val captures: List<CapturedCa>, val eligible: Boolean, val reason: String)
class CleanupTicket internal constructor(val id: String, val inventory: ScanInventory, val targets: List<CleanupTarget>, val expiresAt: Long) {
    val backupCount get() = targets.sumOf { it.captures.size }
}
enum class CleanupPhase { SCAN, BACKUP, PREFLIGHT, DELETE, VERIFY, DONE }
data class CleanupProgress(val phase: CleanupPhase, val completed: Int, val total: Int)

object CleanupVerification {
    fun review(history: CleanupHistory, scan: ScanInventory): CleanupReview {
        val userKeys = scan.userCertificates.map { it.key }.toSet()
        val removed = history.entries.filter { it.status == CleanupStatus.REMOVED || it.fileMoved }
        val removedFps = removed.map { it.fingerprint }.toSet()
        val modules = scan.observations.filter { it.source == CertSource.MODULE }.map { it.fingerprint }.toSet()
        val newSystem = scan.records.filter { it.source == CertSource.SYSTEM }.map { it.fingerprint }.toSet() - history.systemFingerprints
        return CleanupReview(scan.userCertificates.size, history.entries.filter { it.key in userKeys }.map { it.key },
            removed.filter { entry ->
                if (entry.fileMoved) scan.observations.any { it.key == entry.key && RootFilePolicy.eligible(it) } else entry.key in userKeys
            }.map { it.key },
            ((modules intersect history.entries.map { it.fingerprint }.toSet()) + (newSystem intersect removedFps)).sorted(),
            if (history.bootMarker == null || scan.bootMarker == null) null else history.bootMarker != scan.bootMarker,
            scan.duplicates)
    }
}

/** Durable local checkpoints contain metadata only. They never authorize replaying an operation. */
class CleanupHistoryStore(private val file: File) {
    @Synchronized fun save(history: CleanupHistory) {
        require(history.entries.size <= 10_000)
        val properties = Properties().apply {
            setProperty("version", "1"); setProperty("boot", history.bootMarker.orEmpty())
            setProperty("time", history.createdAt.toString()); setProperty("count", history.entries.size.toString())
            setProperty("system", history.systemFingerprints.joinToString(",")); setProperty("warningConfirmed", history.warningGoneConfirmed.toString())
            history.entries.forEachIndexed { i, entry ->
                setProperty("$i.key", entry.key); setProperty("$i.fp", entry.fingerprint); setProperty("$i.user", entry.userId.toString())
                setProperty("$i.backups", entry.backupIds.joinToString(",")); setProperty("$i.status", entry.status.name)
                setProperty("$i.reason", entry.reason.take(2048))
                setProperty("$i.backupVerified", entry.backupVerified.toString()); setProperty("$i.fileMoved", entry.fileMoved.toString())
                setProperty("$i.movedFiles", entry.movedFiles.toString()); setProperty("$i.activeRechecked", entry.activeRechecked.toString()); setProperty("$i.rebootRechecked", entry.rebootRechecked.toString())
            }
        }
        check(file.parentFile!!.isDirectory || file.parentFile!!.mkdirs())
        val temporary = File.createTempFile("cleanup-", ".tmp", file.parentFile)
        try {
            FileOutputStream(temporary).use { properties.store(it, "CertManager cleanup checkpoint"); it.fd.sync() }
            Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            java.nio.channels.FileChannel.open(file.parentFile!!.toPath(), java.nio.file.StandardOpenOption.READ).use { it.force(true) }
        } finally { temporary.delete() }
    }
    @Synchronized fun load(): CleanupHistory? {
        if (!file.exists()) return null
        require(file.length() in 1..16_777_216)
        val p = Properties().apply { file.inputStream().use(::load) }
        require(p.getProperty("version") == "1")
        val count = p.getProperty("count").toInt(); require(count in 0..10_000)
        val entries = (0 until count).map { i ->
            val fp = p.getProperty("$i.fp"); require(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}").matches(fp))
            val user = p.getProperty("$i.user").toInt(); require(user >= 0)
            val key = p.getProperty("$i.key"); require(key == "USER:$user:$fp")
            val ids = p.getProperty("$i.backups").split(',').filter { it.isNotEmpty() }
            ids.forEach { require(UUID.fromString(it).toString() == it) }
            CleanupEntry(key, fp, user, ids, CleanupStatus.valueOf(p.getProperty("$i.status")), p.getProperty("$i.reason"),
                p.getProperty("$i.backupVerified", "true").toBoolean(), p.getProperty("$i.fileMoved", "false").toBoolean(),
                p.getProperty("$i.activeRechecked", "false").toBoolean(), p.getProperty("$i.rebootRechecked", "false").toBoolean(), p.getProperty("$i.movedFiles", "0").toInt().also { require(it in 0..10000) })
        }
        return CleanupHistory(p.getProperty("boot").ifBlank { null }, p.getProperty("time").toLong(), entries,
            p.getProperty("system").split(',').filter { it.isNotEmpty() }.toSet(), p.getProperty("warningConfirmed", "false").toBoolean())
    }
}

/** Two confirmations are rendered by the UI. This class cannot delete until its prepared ticket is committed. */
class CleanupCoordinator(private val gateway: CleanupGateway, private val backups: BackupStore,
    private val historyStore: CleanupHistoryStore) {
    private var pending: CleanupTicket? = null
    @Synchronized fun cancel(ticket: CleanupTicket) { if (pending === ticket) pending = null }
    @Synchronized fun prepare(progress: (CleanupProgress) -> Unit = {}): CleanupTicket {
        pending = null
        check(gateway.rootAuthorized()) { "Root authorization required" }
        progress(CleanupProgress(CleanupPhase.SCAN, 0, 0))
        val scan = gateway.scanInventory()
        val records = scan.userCertificates
        check(records.isNotEmpty()) { "No observed user CA. Check inaccessible profiles, device policies and uncovered stores if the warning remains." }
        require(records.size <= 10_000) { "Too many certificates for one review" }
        val all = records.flatMap { record -> scan.observations.filter { it.key == record.key } }.distinctBy { it.locator }
        var complete = 0
        val captures = all.map { record ->
            validateUser(record)
            val fresh = gateway.reread(record) ?: error("CA unavailable; no cleanup started. Earlier backups retained.")
            check(fresh.fingerprint == record.fingerprint) { "CA changed; no cleanup started" }
            val backup = backups.create(fresh)
            validateBackup(fresh, backup.id)
            complete++; progress(CleanupProgress(CleanupPhase.BACKUP, complete, all.size))
            CapturedCa(fresh, backup.id)
        }
        val targets = records.map { record ->
            val allowed = gateway.canUninstall(record)
            CleanupTarget(record, captures.filter { it.record.key == record.key }, allowed,
                if (allowed) "" else gateway.uninstallBlockReason(record))
        }
        return CleanupTicket(UUID.randomUUID().toString(), scan, targets, System.currentTimeMillis() + 300_000).also { pending = it }
    }
    private fun validateUser(record: CertificateRecord) {
        require(record.source == CertSource.USER && CertificatePaths.validLocator(record)) { "Only validated user CA sources may be cleaned" }
    }
    private fun validateBackup(record: CertificateRecord, id: String) {
        val backup = backups.load(id)
        check(backup.source == CertSource.USER && backup.userId == record.userId && backup.locator == record.locator &&
            backup.fingerprint == record.fingerprint && backup.raw.contentEquals(record.raw)) { "Backup mismatch; cleanup stopped" }
    }
    private fun revalidate(target: CleanupTarget) {
        validateUser(target.record)
        target.captures.forEach { capture ->
            validateUser(capture.record); validateBackup(capture.record, capture.backupId)
            val fresh = gateway.reread(capture.record) ?: error("CA disappeared or became inaccessible; no further removal")
            check(fresh.fingerprint == capture.record.fingerprint && fresh.raw.contentEquals(capture.record.raw)) { "CA changed; no further removal" }
        }
    }
    @Synchronized fun executeConfirmed(ticket: CleanupTicket, progress: (CleanupProgress) -> Unit = {}): CleanupReport {
        check(pending === ticket) { "Confirmation is stale or already used" }; pending = null
        check(System.currentTimeMillis() <= ticket.expiresAt) { "Confirmation expired; backups retained" }
        check(gateway.rootAuthorized()) { "Root authorization lost; backups retained" }
        progress(CleanupProgress(CleanupPhase.PREFLIGHT, 0, ticket.targets.size))
        // Every backup and every target is revalidated before the FIRST uninstall.
        ticket.targets.forEachIndexed { i, target -> revalidate(target); progress(CleanupProgress(CleanupPhase.PREFLIGHT, i + 1, ticket.targets.size)) }
        var history = CleanupHistory(ticket.inventory.bootMarker, System.currentTimeMillis(), ticket.targets.map { target ->
            CleanupEntry(target.record.key, target.record.fingerprint, target.record.userId,
                target.captures.map { it.backupId }, CleanupStatus.PENDING, "")
        }, ticket.inventory.records.filter { it.source == CertSource.SYSTEM }.map { it.fingerprint }.toSet())
        historyStore.save(history) // A failed durable checkpoint prevents starting deletion.
        ticket.targets.forEachIndexed { i, target ->
            var movedFiles = 0
            val result = if (!target.eligible || !gateway.canUninstall(target.record)) {
                CleanupStatus.SKIPPED to gateway.uninstallBlockReason(target.record)
            } else try {
                check(gateway.rootAuthorized()) { "Root authorization lost" }
                revalidate(target)
                val fileTargets = target.captures.filter { it.record.fileMetadata != null && RootFilePolicy.eligible(it.record) }
                if (fileTargets.isEmpty()) gateway.uninstall(target.record)
                else fileTargets.forEach { gateway.uninstall(it.record); movedFiles++ }
                val scan = gateway.scanInventory()
                val rootMove = target.captures.any { it.record.fileMetadata != null } && RootFilePolicy.eligible(target.record)
                val fileAbsent = scan.observations.none { it.key == target.record.key && RootFilePolicy.eligible(it) } &&
                    scan.coverage.any { it.location == target.record.locator.substringBeforeLast('/') && it.readable }
                val absent = !rootMove && !gateway.installed(target.record.fingerprint, target.record.userId) &&
                    scan.userCertificates.none { it.key == target.record.key } && scan.evidenceReadable(target.record)
                if (rootMove && fileAbsent) CleanupStatus.FILE_MOVED to "Root file-level uninstall: active file absent; reboot and review required; warning not confirmed"
                else if (absent) CleanupStatus.REMOVED to "" else CleanupStatus.UNVERIFIED to "Removal not verified in all original sources; backup retained"
            } catch (e: Exception) { CleanupStatus.FAILED to (e.message ?: e.javaClass.simpleName) }
            history = history.copy(entries = history.entries.mapIndexed { index, entry -> if (index == i) entry.copy(status = result.first, reason = result.second, fileMoved = movedFiles > 0, activeRechecked = movedFiles > 0, movedFiles = movedFiles) else entry })
            historyStore.save(history) // Stop if checkpoint persistence fails; never replay automatically.
            progress(CleanupProgress(CleanupPhase.DELETE, i + 1, ticket.targets.size))
        }
        progress(CleanupProgress(CleanupPhase.VERIFY, 0, 0))
        val finalScan = gateway.scanInventory()
        val review = CleanupVerification.review(history, finalScan)
        // A target can reappear during the batch; do not leave an earlier success unqualified.
        history = history.copy(entries = history.entries.map { entry ->
            val target = ticket.targets.first { it.record.key == entry.key }
            if (entry.status == CleanupStatus.REMOVED && (entry.key in review.targetedRemaining || !finalScan.evidenceReadable(target.record)))
                entry.copy(status = CleanupStatus.UNVERIFIED, reason = "Final scan found residual CA or lost source visibility; backup retained") else entry
        })
        historyStore.save(history)
        progress(CleanupProgress(CleanupPhase.DONE, ticket.targets.size, ticket.targets.size))
        return CleanupReport(history, finalScan, review)
    }
}
