package com.certmanager.android

import com.certmanager.android.domain.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class CleanupTests {
    @get:Rule val temporary = TemporaryFolder()
    private fun bytes(name: String = "test-ca.der") = javaClass.classLoader!!.getResourceAsStream(name)!!.use { it.readBytes() }
    private fun record(name: String = "test-ca.der", user: Int = 0, filename: String = "012345ab.0"): CertificateRecord {
        val raw = bytes(name)
        return CertificateRecord(Certificates.parse(raw), raw, CertSource.USER, user, "/data/misc/user/$user/cacerts-added/$filename", observedByKeyStore = true)
    }
    private fun inventory(records: List<CertificateRecord>, boot: String? = "boot:1", inaccessible: Boolean = false) = ScanInventory(0, records,
        (records.filter { it.userId >= 0 }.map { it.userId } + 0).toSet(),
        records.flatMap { record -> record.origins.map { path ->
            StoreCoverage(if (path.startsWith("keystore:")) "keystore:${record.userId}" else path.substringBeforeLast('/'), !inaccessible)
        } }.distinctBy { it.location }, bootMarker = boot)
    private class Gateway(initial: List<CertificateRecord>) : CleanupGateway {
        val records = initial.toMutableList()
        val failed = mutableSetOf<String>(); val skipped = mutableSetOf<String>()
        var root = true; var deletes = 0; var boot = "boot:1"; var denyVerification = false
        var disappearOnRead: String? = null
        var failedLocator: String? = null
        var afterDelete: (() -> Unit)? = null
        override fun rootAuthorized() = root
        override fun reread(record: CertificateRecord): CertificateRecord? = if (record.locator == disappearOnRead) null else records.find { it.locator == record.locator }
        override fun canUninstall(record: CertificateRecord) = record.source == CertSource.USER && record.key !in skipped
        override fun uninstallBlockReason(record: CertificateRecord) = "Unsupported profile / no verified uninstall API"
        override fun uninstall(record: CertificateRecord) {
            deletes++
            if (record.key in failed || record.locator == failedLocator) error("Simulated service failure")
            records.removeAll { if (record.fileMetadata != null) it.locator == record.locator else it.key == record.key }; afterDelete?.invoke()
        }
        override fun installed(fingerprint: String, userId: Int) = records.any { it.source == CertSource.USER && it.fingerprint == fingerprint && it.userId == userId }
        override fun scanInventory(): ScanInventory {
            // A successfully read empty directory stays in the coverage set after removal.
            val dirs = listOf("/data/misc/user/0/cacerts-added", "/data/misc/user/10/cacerts-added", "keystore:0")
            return ScanInventory(0, records.toList(), setOf(0, 10), dirs.map { StoreCoverage(it, !denyVerification) }, bootMarker = boot)
        }
    }
    private data class Harness(val gateway: Gateway, val backups: BackupStore, val history: CleanupHistoryStore,
        val coordinator: CleanupCoordinator, val directory: File)
    private fun harness(records: List<CertificateRecord>, backupFailure: Boolean = false): Harness {
        val folder = temporary.newFolder()
        val directory = File(folder, "backups")
        if (backupFailure) directory.writeText("not a directory")
        val backups = BackupStore(directory); val gateway = Gateway(records)
        val history = CleanupHistoryStore(File(folder, "history.properties"))
        return Harness(gateway, backups, history, CleanupCoordinator(gateway, backups, history), directory)
    }
    private inline fun fails(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        throw AssertionError("Expected failure")
    }
    @Test fun scannerClassifiesUsersSystemModulesAndDisabledRecords() {
        val raw = bytes()
        val cases = listOf("/data/misc/user/10/cacerts-added/012345ab.0" to CertSource.USER,
            "/data/misc_ce/11/cacerts-added/012345ab.0" to CertSource.USER,
            "/system/etc/security/cacerts/012345ab.0" to CertSource.SYSTEM,
            "/apex/com.android.conscrypt/cacerts/012345ab.0" to CertSource.SYSTEM,
            "/data/adb/modules/ca_module/system/etc/security/cacerts/012345ab.0" to CertSource.MODULE,
            "/data/adb/modules/ca_module/certs/custom.crt" to CertSource.MODULE)
        cases.forEach { (path, source) ->
            val observation = InventoryFiles.inspect(path, raw, 0)
            assertEquals(source, observation.certificate!!.source); assertNull(observation.disabled)
            assertTrue(CertificatePaths.validLocator(observation.certificate))
        }
        val disabled = InventoryFiles.inspect("/data/misc/user/10/cacerts-removed/012345ab.0", byteArrayOf(), 0)
        assertNull(disabled.certificate); assertEquals(10, disabled.disabled!!.userId)
        assertFalse(CertificatePaths.validLocator(record().copy(locator = "/data/misc/user/0/cacerts-removed/012345ab.0")))
        assertFalse(CertificatePaths.validLocator(record().copy(source = CertSource.SYSTEM)))
    }
    @Test fun moduleCommandsRejectTraversalAndNeverExecuteScripts() {
        listOf("../bad", "x;reboot", "x'", "$(id)", "-option", "a/b").forEach { id -> fails { ShellPolicy.script(RootCommand.ModuleStatus(id)) } }
        val command = ShellPolicy.script(RootCommand.ModuleStatus("my_ca"))
        assertTrue(command.contains("grep -qiE")); assertFalse(command.contains("sh '")); assertFalse(command.contains("rm "))
        assertFalse(CertificatePaths.isCertificate("/data/adb/modules/my_ca/certs/../../private.crt"))
    }
    @Test fun duplicateDetectionKeepsAllSourceEvidenceWithoutCountingApiMirrorTwice() {
        val first = record()
        val api = first.copy(locator = "keystore:user:012345ab.0", origins = listOf("keystore:user:012345ab.0"))
        val scan = inventory(listOf(first, api))
        assertEquals(1, scan.userCertificates.size); assertEquals(2, scan.userCertificates.single().origins.size)
        assertTrue(scan.duplicates.isEmpty())
        val duplicate = first.copy(locator = "/data/misc/user/0/cacerts-added/012345ab.1", origins = listOf("/data/misc/user/0/cacerts-added/012345ab.1"))
        val repeated = inventory(listOf(first, api, duplicate, record(user = 10)))
        assertEquals(2, repeated.userCertificates.size); assertEquals(1, repeated.duplicates.size)
    }
    @Test fun scanReadFailureRemainsExplicitlyUnknown() {
        val scan = inventory(listOf(record()), inaccessible = true)
        assertFalse(scan.evidenceReadable(record()))
        assertTrue(scan.coverage.any { !it.readable })
        val parentReadable = inventory(listOf(record()))
        assertFalse(parentReadable.copy(coverage = parentReadable.coverage + StoreCoverage(record().locator, false)).evidenceReadable(record()))
    }
    @Test fun preparationBacksUpEverySourceBeforeAnyDeleteAndPreservesRawBytes() {
        val first = record(); val second = record("cleanup-ca.der", filename = "fedcba98.0")
        val api = first.copy(locator = "keystore:user:012345ab.0", origins = listOf("keystore:user:012345ab.0"))
        val h = harness(listOf(first, second, api)); val ticket = h.coordinator.prepare()
        assertEquals(0, h.gateway.deletes); assertEquals(3, ticket.backupCount); assertEquals(2, ticket.targets.size)
        ticket.targets.flatMap { it.captures }.forEach { capture -> assertArrayEquals(capture.record.raw, h.backups.load(capture.backupId).raw) }
        assertNull(h.history.load())
    }
    @Test fun backupFailurePreventsEveryUninstall() {
        val h = harness(listOf(record()), backupFailure = true)
        fails { h.coordinator.prepare() }; assertEquals(0, h.gateway.deletes)
    }
    @Test fun laterPreparationFailureRetainsEarlierBackupWithoutDeletingAnything() {
        val first = record(); val second = record("cleanup-ca.der", filename = "fedcba98.0")
        val h = harness(listOf(first, second)); h.gateway.disappearOnRead = second.locator
        fails { h.coordinator.prepare() }; assertEquals(0, h.gateway.deletes); assertEquals(1, h.backups.list().size)
    }
    @Test fun cancelledTicketCannotDeleteAndBackupsRemain() {
        val h = harness(listOf(record())); val ticket = h.coordinator.prepare(); h.coordinator.cancel(ticket)
        fails { h.coordinator.executeConfirmed(ticket) }; assertEquals(0, h.gateway.deletes); assertEquals(1, h.backups.list().size)
    }
    @Test fun corruptedLastBackupPreventsFirstDeletion() {
        val h = harness(listOf(record(), record("cleanup-ca.der", filename = "fedcba98.0")))
        val ticket = h.coordinator.prepare()
        val backup = ticket.targets.last().captures.last().backupId
        File(h.directory, "$backup.cmb").writeBytes(byteArrayOf(1, 2, 3))
        fails { h.coordinator.executeConfirmed(ticket) }; assertEquals(0, h.gateway.deletes)
    }
    @Test fun finalTargetChangedAfterConfirmationPreparationPreventsFirstDeletion() {
        val first = record(); val second = record("cleanup-ca.der", filename = "fedcba98.0")
        val h = harness(listOf(first, second)); val ticket = h.coordinator.prepare()
        h.gateway.records[1] = second.copy(raw = Certificates.pem(second.certificate))
        fails { h.coordinator.executeConfirmed(ticket) }; assertEquals(0, h.gateway.deletes)
    }
    @Test fun rootRevocationStopsCleanupWithBackupsRetained() {
        val h = harness(listOf(record())); val ticket = h.coordinator.prepare(); h.gateway.root = false
        fails { h.coordinator.executeConfirmed(ticket) }; assertEquals(0, h.gateway.deletes); assertEquals(1, h.backups.list().size)
    }
    @Test fun partialSuccessAndSkippedProfilesAreReportedIndividually() {
        val first = record(); val second = record("cleanup-ca.der", filename = "fedcba98.0"); val other = record(user = 10)
        val module = first.copy(source = CertSource.MODULE, userId = -1, locator = "/data/adb/modules/ca/cacerts/012345ab.0")
        val h = harness(listOf(first, second, other, module))
        h.gateway.failed += second.key; h.gateway.skipped += other.key
        val report = h.coordinator.executeConfirmed(h.coordinator.prepare())
        assertEquals(1, report.history.entries.count { it.status == CleanupStatus.REMOVED })
        assertEquals(1, report.history.entries.count { it.status == CleanupStatus.FAILED })
        assertEquals(1, report.history.entries.count { it.status == CleanupStatus.SKIPPED })
        assertEquals(2, h.gateway.deletes); assertEquals(3, h.backups.list().size)
        assertEquals(2, report.review.remaining); assertTrue(h.gateway.records.any { it.source == CertSource.MODULE })
        assertEquals(3, h.history.load()!!.entries.size)
    }
    @Test fun removedFileWithLostCoverageIsNotReportedAsVerifiedSuccess() {
        val h = harness(listOf(record())); val ticket = h.coordinator.prepare()
        h.gateway.afterDelete = { h.gateway.denyVerification = true }
        val report = h.coordinator.executeConfirmed(ticket)
        assertEquals(CleanupStatus.UNVERIFIED, report.history.entries.single().status)
    }
    @Test fun rebootReviewPersistsAcrossProcessRestartAndDetectsReappearingCa() {
        val first = record(); val h = harness(listOf(first))
        val report = h.coordinator.executeConfirmed(h.coordinator.prepare())
        assertEquals(CleanupStatus.REMOVED, report.history.entries.single().status)
        val store = CleanupHistoryStore(File(h.directory.parentFile, "history.properties"))
        val restored = store.load()!!
        h.gateway.boot = "boot:2"; h.gateway.records += first
        val module = first.copy(source = CertSource.MODULE, userId = -1,
            locator = "/data/adb/modules/ca/cacerts/012345ab.0", origins = listOf("/data/adb/modules/ca/cacerts/012345ab.0"))
        h.gateway.records += module
        val review = CleanupVerification.review(restored, h.gateway.scanInventory())
        assertEquals(true, review.rebootDetected); assertEquals(listOf(first.key), review.reappeared)
        assertEquals(listOf(first.fingerprint), review.possibleInjection)
        assertEquals(1, h.gateway.deletes) // A review never automatically repeats deletion.
    }
    @Test fun bootMarkerUnknownNeverClaimsRebootOrWarningResolution() {
        val first = record(); val history = CleanupHistory(null, 0, emptyList(), emptySet())
        val review = CleanupVerification.review(history, inventory(listOf(first), null))
        assertNull(review.rebootDetected); assertEquals(1, review.remaining)
    }
    @Test fun systemAndModuleOnlyInventoryCannotBecomeCleanupTargets() {
        val first = record().copy(source = CertSource.SYSTEM, locator = "/system/etc/security/cacerts/012345ab.0")
        val h = harness(listOf(first)); fails { h.coordinator.prepare() }; assertEquals(0, h.gateway.deletes)
    }
    @Test fun rootRevokedAfterFirstRemovalPreventsSecondRemoval() {
        val h = harness(listOf(record(), record("cleanup-ca.der", filename = "fedcba98.0")))
        val ticket = h.coordinator.prepare()
        h.gateway.afterDelete = { h.gateway.root = false }
        val report = h.coordinator.executeConfirmed(ticket)
        assertEquals(1, h.gateway.deletes)
        assertEquals(1, report.history.entries.count { it.status == CleanupStatus.FAILED })
        assertEquals(2, h.backups.list().size)
    }
    @Test fun reappearingTargetDuringCleanupNeverReportsSuccess() {
        val first = record(); val h = harness(listOf(first)); val ticket = h.coordinator.prepare()
        h.gateway.afterDelete = { h.gateway.records += first }
        val report = h.coordinator.executeConfirmed(ticket)
        assertEquals(CleanupStatus.UNVERIFIED, report.history.entries.single().status)
        assertEquals(1, report.review.remaining); assertEquals(1, h.gateway.deletes)
    }
    @Test fun checkpointFailurePreventsAnyUninstall() {
        val h = harness(listOf(record()))
        val parentFile = temporary.newFile()
        val history = CleanupHistoryStore(File(parentFile, "checkpoint.properties"))
        val coordinator = CleanupCoordinator(h.gateway, h.backups, history)
        val ticket = coordinator.prepare()
        fails { coordinator.executeConfirmed(ticket) }
        assertEquals(0, h.gateway.deletes); assertEquals(1, h.backups.list().size)
    }

    private val fileMetadata = FileMetadata("1\t1\t2\t1000\t1000\t420\t1000\t1\t0\t1\t0\t1\t3\tu:object_r:system_data_file:s0")
    @Test fun rootBatchPartialFailurePreservesEachBackupAndDoesNotClaimWarningGone() {
        val first = record().copy(fileMetadata = fileMetadata)
        val second = record("cleanup-ca.der", filename = "fedcba98.0").copy(fileMetadata = fileMetadata)
        val h = harness(listOf(first, second)); h.gateway.failed += second.key
        val report = h.coordinator.executeConfirmed(h.coordinator.prepare())
        assertEquals(CleanupStatus.FILE_MOVED, report.history.entries.first().status)
        assertEquals(CleanupStatus.FAILED, report.history.entries.last().status)
        assertEquals(1, report.history.entries.sumOf { it.movedFiles })
        assertFalse(report.history.warningGoneConfirmed)
        assertEquals(2, h.backups.list().size)
    }
    @Test fun sameFingerprintCopiesAreProcessedIndividuallyAndPartialMoveIsRecorded() {
        val first = record().copy(fileMetadata = fileMetadata)
        val path = "/data/misc/user/0/cacerts-added/012345ab.1"
        val second = first.copy(locator = path, origins = listOf(path))
        val h = harness(listOf(first, second)); h.gateway.failedLocator = path
        val report = h.coordinator.executeConfirmed(h.coordinator.prepare())
        val entry = report.history.entries.single()
        assertEquals(CleanupStatus.FAILED, entry.status)
        assertTrue(entry.fileMoved); assertEquals(1, entry.movedFiles)
        assertEquals(2, entry.backupIds.size); assertEquals(2, h.backups.list().size)
        assertEquals(1, report.inventory.userCertificates.size)
    }

}
