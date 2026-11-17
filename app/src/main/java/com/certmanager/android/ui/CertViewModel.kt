package com.certmanager.android.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.certmanager.android.data.CertificateRepository
import com.certmanager.android.data.RootShell
import com.certmanager.android.domain.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

 data class UiState(
    val loading: Boolean = false,
    val rootGranted: Boolean = false,
    val rootRequested: Boolean = false,
    val records: List<CertificateRecord> = emptyList(),
    val backups: List<Backup> = emptyList(),
    val users: Set<Int> = emptySet(),
    val notes: List<String> = emptyList(),
    val error: String? = null,
    val selected: CertificateRecord? = null,
    val deleteTicket: DeleteTicket? = null,
    val installCandidate: InstallCandidate? = null,
    val inventory: ScanInventory? = null,
    val safeCleanupKeys: Set<String> = emptySet(),
    val cleanupWarning: Boolean = false,
    val cleanupTicket: CleanupTicket? = null,
    val cleanupProgress: CleanupProgress? = null,
    val cleanupHistory: CleanupHistory? = null,
    val cleanupReview: CleanupReview? = null
)
data class InstallCandidate(val raw: ByteArray, val fingerprint: String, val backupId: String? = null)
sealed interface UiEvent {
    data class Export(val bytes: ByteArray, val filename: String, val mime: String) : UiEvent
    data class Install(val candidate: InstallCandidate) : UiEvent
    data class Settings(val record: CertificateRecord? = null) : UiEvent
    data class Message(val key: String) : UiEvent
}

class CertViewModel(application: Application) : AndroidViewModel(application) {
    val repository = CertificateRepository(application, RootShell())
    private val mutable = MutableStateFlow(UiState())
    val state = mutable.asStateFlow()
    private val channel = Channel<UiEvent>(Channel.BUFFERED)
    val events = channel.receiveAsFlow()
    // Keep document/Settings flows across configuration changes; never store certificate bytes in a Bundle.
    var externalExport: UiEvent.Export? = null
    var externalInstall: InstallCandidate? = null
    var externalDelete: CertificateRecord? = null
    var archiveImport = false
    var savingForInstall = false
    private var busy = false
    init { refresh() }
    private fun work(action: suspend () -> Unit) {
        if (busy) return
        busy = true
        mutable.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            try { withContext(Dispatchers.IO) { action() } }
            catch (e: Exception) { mutable.update { it.copy(error = e.message ?: e.javaClass.simpleName) } }
            finally {
                mutable.update { it.copy(loading = false, rootGranted = repository.root.authorized) }
                busy = false
            }
        }
    }
    private fun load() {
        val snapshot = repository.scan()
        val backups = repository.backups.inspect()
        val history = repository.cleanupHistory.load()
        val safe = snapshot.inventory.userCertificates.filter(repository::canUninstall).map { it.key }.toSet()
        mutable.update { old -> old.copy(records = snapshot.records, users = snapshot.users, notes = snapshot.notes + backups.errors,
            backups = backups.valid, inventory = snapshot.inventory, safeCleanupKeys = safe,
            cleanupHistory = history, cleanupReview = history?.let { CleanupVerification.review(it, snapshot.inventory) }, selected = old.selected?.let { s -> snapshot.records.find { it.key == s.key } }) }
    }
    fun refresh() = work { load() }
    fun requestRoot() = work {
        val granted = repository.root.request()
        mutable.update { it.copy(rootRequested = true, rootGranted = granted) }
        load()
        if (!granted) error("Root denied or unavailable. Check Magisk / KernelSU / APatch authorization.")
    }
    fun select(record: CertificateRecord?) { mutable.update { it.copy(selected = record) } }
    fun clearError() { mutable.update { it.copy(error = null) } }
    fun reportError(message: String) { mutable.update { it.copy(error = message) } }
    fun backup(record: CertificateRecord) = work {
        val fresh = repository.reread(record) ?: error("Certificate unavailable")
        check(fresh.fingerprint == record.fingerprint) { "Certificate changed" }
        repository.backups.create(fresh)
        load(); channel.send(UiEvent.Message("backed_up"))
    }
    fun prepareDelete(record: CertificateRecord) = work {
        val ticket = repository.operations.prepareDelete(record)
        load(); mutable.update { it.copy(deleteTicket = ticket) }
    }
    fun cancelDelete() {
        mutable.value.deleteTicket?.let(repository.operations::cancel)
        mutable.update { it.copy(deleteTicket = null) }
    }
    fun confirmDelete() {
        val ticket = mutable.value.deleteTicket ?: return
        mutable.update { it.copy(deleteTicket = null) }
        work {
            val result = repository.operations.deleteConfirmed(ticket)
            load()
            if (result == DeleteResult.REMOVED) {
                check(mutable.value.inventory?.userCertificates?.none { it.key == ticket.record.key } == true &&
                    mutable.value.inventory?.evidenceReadable(ticket.record) == true) { "Residual user CA found after removal; backup retained" }
                channel.send(UiEvent.Message("removed"))
            }
            else {
                check(ticket.record.userId == repository.currentUserId) { "Open system settings in the original Android profile; backup retained" }
                channel.send(UiEvent.Settings(ticket.record))
            }
        }
    }
    fun afterSettings(record: CertificateRecord?) = work {
        load()
        if (record != null) {
            check(record.observedByKeyStore) { "This CA was only visible as a store file. Its removal cannot be verified through AndroidCAStore; check system settings. Backup retained." }
            check(!repository.installed(record.fingerprint, record.userId)) { "Removal not observed by AndroidCAStore; backup retained" }
            check(mutable.value.inventory?.userCertificates?.none { it.key == record.key } == true &&
                mutable.value.inventory?.evidenceReadable(record) == true) { "Residual CA or unreadable original store; removal not verified. Backup retained." }
            channel.send(UiEvent.Message("removed"))
        }
    }
    fun export(record: CertificateRecord, pem: Boolean) = work {
        channel.send(UiEvent.Export(if (pem) Certificates.pem(record.certificate) else record.raw,
            "ca-${record.fingerprint.replace(":", "").take(16)}.${if (pem) "pem" else "cer"}", "application/x-x509-ca-cert"))
    }
    fun exportBackup(backup: Backup, archive: Boolean) = work {
        val verified = repository.backups.load(backup.id)
        channel.send(UiEvent.Export(if (archive) repository.backups.bytes(verified.id) else verified.raw,
            "backup-${verified.id}.${if (archive) "cmb" else "cer"}", "application/octet-stream"))
    }
    fun prepareRestore(backup: Backup) = work {
        check(repository.rootAuthorized()) { "Root authorization required; backup retained" }
        load()
        val verified = repository.backups.load(backup.id)
        val bytes = repository.operations.prepareRestore(verified, mutable.value.records, repository.currentUserId)
        mutable.update { it.copy(installCandidate = InstallCandidate(bytes, verified.fingerprint, verified.id)) }
    }
    fun importBytes(bytes: ByteArray, archive: Boolean) = work {
        check(repository.rootAuthorized()) { "Root authorization required" }
        if (archive) {
            val backup = BackupCodec.decode(bytes)
            // Imported archives are validated and retained privately before attempting restoration.
            val record = CertificateRecord(backup.certificate, backup.raw, backup.source, backup.userId, backup.locator)
            val local = repository.backups.create(record)
            load()
            val der = repository.operations.prepareRestore(local, mutable.value.records, repository.currentUserId)
            mutable.update { it.copy(installCandidate = InstallCandidate(der, local.fingerprint, local.id)) }
        } else {
            val cert = repository.checkImport(bytes)
            mutable.update { it.copy(installCandidate = InstallCandidate(cert.encoded, Certificates.fingerprint(cert.encoded))) }
        }
    }
    fun cancelInstall() { mutable.update { it.copy(installCandidate = null) } }
    fun confirmInstall() {
        val candidate = mutable.value.installCandidate ?: return
        mutable.update { it.copy(installCandidate = null) }
        work {
            check(repository.rootAuthorized()) { "Root authorization required; backup retained" }
            repository.checkImport(candidate.raw) // Check duplicates again at confirmation.
            channel.send(UiEvent.Install(candidate))
        }
    }
    fun afterInstall(candidate: InstallCandidate) = work {
        load()
        candidate.backupId?.let { repository.operations.verifyRestore(repository.backups.load(it)) }
        check(repository.installed(candidate.fingerprint, repository.currentUserId)) { "Installation not observed. The certificate may not have been installed; backup retained." }
        channel.send(UiEvent.Message("installed"))
    }
    fun showCleanupWarning() { if (!busy) mutable.update { it.copy(cleanupWarning = true) } }
    fun dismissCleanupWarning() { mutable.update { it.copy(cleanupWarning = false) } }
    fun prepareCleanup() {
        dismissCleanupWarning()
        work {
            mutable.update { it.copy(cleanupProgress = CleanupProgress(CleanupPhase.SCAN, 0, 0)) }
            try {
                val ticket = repository.cleanup.prepare { progress -> mutable.update { it.copy(cleanupProgress = progress) } }
                load()
                mutable.update { it.copy(cleanupTicket = ticket) }
            } finally {
                // Earlier successful backups remain visible even when a later backup fails.
                mutable.update { it.copy(backups = repository.backups.inspect().valid) }
            }
        }
    }
    fun cancelCleanup() {
        mutable.value.cleanupTicket?.let(repository.cleanup::cancel)
        mutable.update { it.copy(cleanupTicket = null, cleanupProgress = null) }
    }
    fun confirmCleanup() {
        val ticket = mutable.value.cleanupTicket ?: return
        if (busy) return
        mutable.update { it.copy(cleanupTicket = null) }
        work {
            try {
                val report = repository.cleanup.executeConfirmed(ticket) { progress -> mutable.update { it.copy(cleanupProgress = progress) } }
                load()
                mutable.update { it.copy(cleanupHistory = report.history, cleanupReview = report.review) }
            } catch (e: Exception) {
                load() // Rescan after partial failure; never discard the durable checkpoint or backups.
                throw e
            }
        }
    }
    fun reviewAfterReboot() = work {
        check(repository.rootAuthorized()) { "Grant Root before reviewing all accessible stores" }
        mutable.update { it.copy(cleanupProgress = CleanupProgress(CleanupPhase.VERIFY, 0, 0)) }
        load()
        mutable.update { it.copy(cleanupProgress = CleanupProgress(CleanupPhase.DONE, 0, 0)) }
    }
    fun openSettings() = work { channel.send(UiEvent.Settings()) }
}
