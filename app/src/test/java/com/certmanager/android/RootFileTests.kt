package com.certmanager.android

import com.certmanager.android.data.RootShell
import com.certmanager.android.domain.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.*
import java.util.concurrent.TimeUnit

class RootFileTests {
    @get:Rule val temporary = TemporaryFolder()
    private val metadata = FileMetadata("1\t1\t2\t1000\t1000\t420\t1000\t1\t0\t1\t0\t1\t3\tu:object_r:system_data_file:s0")
    private fun record(user: Int = 0): CertificateRecord {
        val raw = javaClass.classLoader!!.getResourceAsStream("test-ca.pem")!!.use { it.readBytes() }
        return CertificateRecord(Certificates.parse(raw), raw, CertSource.USER, user,
            "/data/misc/user/$user/cacerts-added/012345ab.0", fileMetadata = metadata)
    }
    private fun fails(block: () -> Unit) { try { block() } catch (_: Exception) { return }; fail("Expected failure") }
    private class Filesystem(var current: RootFileSnapshot?) : RootCertificateFiles {
        var root = true; var users = setOf(0, 10); var duplicate = false
        var snapshotError: String? = null; var moveError: String? = null; var restoreError: String? = null
        var moved = 0; var restored = 0; var reappear = false
        override fun authorized() = root
        override fun verifiedUsers() = users
        override fun snapshot(record: CertificateRecord): RootFileSnapshot? {
            snapshotError?.let { error(it) }; return current
        }
        override fun move(backup: Backup) {
            moveError?.let { error(it) }; moved++
            if (!reappear) current = null
        }
        override fun restore(backup: Backup) {
            restoreError?.let { error(it) }; restored++
            current = RootFileSnapshot(backup.raw, backup.fileMetadata!!)
        }
        override fun duplicates(fingerprint: String, userId: Int) = duplicate
    }
    private fun fs(record: CertificateRecord = record()) = Filesystem(RootFileSnapshot(record.raw, metadata))
    private fun store() = BackupStore(temporary.newFolder())
    @Test fun metadataRoundTripRetainsOwnerModeContextAndExactBytes() {
        val b = store().create(record()); val read = BackupCodec.decode(BackupCodec.encode(b))
        assertEquals(metadata, read.fileMetadata); assertEquals(1000, read.fileMetadata!!.uid)
        assertEquals(420, read.fileMetadata.mode); assertArrayEquals(record().raw, read.raw)
        assertNotEquals(b.fingerprint.replace(":", ""), b.rawDigest) // PEM digest is not the DER fingerprint.
    }
    @Test fun legacyVersionOneBackupsRemainReadableWithoutRootMetadata() {
        val b = store().create(record())
        val stream = ByteArrayOutputStream()
        DataOutputStream(stream).use { out ->
            out.writeUTF("CertManagerBackup/1"); out.writeUTF(b.id); out.writeLong(b.createdAt)
            out.writeUTF(b.source.name); out.writeInt(b.userId); out.writeUTF(b.locator)
            out.writeUTF(b.fingerprint); out.writeUTF(b.rawDigest); out.writeInt(b.raw.size); out.write(b.raw)
        }
        val old = BackupCodec.decode(stream.toByteArray()); assertNull(old.fileMetadata); assertArrayEquals(b.raw, old.raw)
    }
    @Test fun rootFilePolicyRejectsTraversalNamesUnknownAndSystemSources() {
        val r = record()
        listOf("/data/misc/user/0/cacerts-added/../012345ab.0", "/data/misc/user/00/cacerts-added/012345ab.0",
            "/data/misc/user/0/cacerts-added/x.pem", "/data/misc/user/0/cacerts-added", "/system/etc/security/cacerts/012345ab.0",
            "/data/misc_ce/0/cacerts-added/012345ab.0", "/data/misc/user/0/cacerts-added/012345ab.0;id").forEach {
            assertFalse(RootFilePolicy.eligible(r.copy(locator = it)))
        }
        assertFalse(RootFilePolicy.eligible(r.copy(source = CertSource.SYSTEM)))
        assertFalse(RootFilePolicy.eligible(r.copy(source = CertSource.MODULE)))
        fails { RootFilePolicy.validate(r, setOf(10)) }
        fails { RootFilePolicy.validate(r.copy(userId = 10), setOf(0, 10)) }
    }
    @Test fun symlinkAndNonRegularFilesAreRejectedByPrivilegedBoundary() {
        for (reason in listOf("O_NOFOLLOW symlink", "Not a regular file", "Profile bind mount detected")) {
            val f = fs().apply { snapshotError = reason }; val b = store()
            fails { RootFileCertificateUninstaller(f, b).capture(record()) }; assertEquals(0, f.moved)
        }
    }
    @Test fun noUninstallWithoutRootAndVerifiedUser() {
        val f = fs().apply { root = false }; val b = store(); b.create(record())
        fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }; assertEquals(0,f.moved)
        f.root = true; f.users = setOf(10)
        fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }; assertEquals(0,f.moved)
    }
    @Test fun uninstallRequiresMatchingMetadataBackup() {
        val f=fs(); val b=store(); val u=RootFileCertificateUninstaller(f,b)
        fails { u.uninstall(record()) }; assertEquals(0,f.moved)
        b.create(record().copy(fileMetadata = null))
        fails { u.uninstall(record()) }; assertEquals(0,f.moved)
    }
    @Test fun inodeChangedAfterBackupPreventsMoveEvenIfCertificateMatches() {
        val f=fs(); val b=store(); b.create(record())
        f.current = RootFileSnapshot(record().raw, FileMetadata(metadata.header.replace("1\t1\t2\t", "1\t1\t99\t")))
        fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }; assertEquals(0,f.moved)
    }
    @Test fun moveAndCrossFilesystemFailuresRetainBackup() {
        for(reason in listOf("rename denied", "EXDEV", "Concurrent path replacement; rolled back")) {
            val f=fs().apply { moveError=reason }; val b=store(); val backup=b.create(record())
            fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }
            assertArrayEquals(record().raw,b.load(backup.id).raw); assertEquals(0,f.moved)
        }
    }
    @Test fun corruptedBackupNeverReachesMove() {
        val directory=temporary.newFolder(); val b=BackupStore(directory); val backup=b.create(record()); val f=fs()
        File(directory,"${backup.id}.cmb").writeBytes(byteArrayOf(1,2,3))
        fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }; assertEquals(0,f.moved)
    }
    @Test fun successfulMoveRequiresActiveFileAbsenceAndRetainsBytes() {
        val f=fs(); val b=store(); val backup=b.create(record())
        RootFileCertificateUninstaller(f,b).uninstall(record()); assertEquals(1,f.moved); assertNull(f.current)
        assertArrayEquals(record().raw,b.load(backup.id).raw)
    }
    @Test fun immediateReappearanceIsFailureAndNeverRetriesDeletion() {
        val f=fs().apply { reappear=true }; val b=store(); b.create(record())
        fails { RootFileCertificateUninstaller(f,b).uninstall(record()) }; assertEquals(1,f.moved); assertEquals(1,b.list().size)
    }
    @Test fun restoreRejectsExistingTargetAndDuplicateBeforeConfirmation() {
        val b=store(); val backup=b.create(record()); val f=fs(); val restorer=RootFileCertificateRestorer(f,b)
        fails { restorer.prepare(backup.id) }; assertEquals(0,f.restored)
        f.current=null; f.duplicate=true; fails { restorer.prepare(backup.id) }; assertEquals(0,f.restored)
    }
    @Test fun restoreRevalidatesTargetAndDuplicateAtCommit() {
        for (duplicate in listOf(false,true)) {
            val b=store(); val backup=b.create(record()); val f=Filesystem(null); val r=RootFileCertificateRestorer(f,b)
            val ticket=r.prepare(backup.id)
            if(duplicate) f.duplicate=true else f.current=RootFileSnapshot(record().raw,metadata)
            fails { r.confirmed(ticket) }; assertEquals(0,f.restored); assertEquals(1,b.list().size)
        }
    }
    @Test fun restorePermissionAndSelinuxFailuresPreserveBackup() {
        for(reason in listOf("fchown failed", "fchmod failed", "fsetxattr security.selinux denied", "Atomic no-replace rename failed")) {
            val b=store(); val backup=b.create(record()); val f=Filesystem(null).apply { restoreError=reason }
            val r=RootFileCertificateRestorer(f,b); val ticket=r.prepare(backup.id)
            fails { r.confirmed(ticket) }; assertEquals(0,f.restored); assertArrayEquals(record().raw,b.load(backup.id).raw)
        }
    }
    @Test fun restoreNeedsExplicitSingleUseConfirmationAndValidatesMetadata() {
        val b=store(); val backup=b.create(record()); val f=Filesystem(null); val r=RootFileCertificateRestorer(f,b)
        val ticket=r.prepare(backup.id); assertEquals(0,f.restored)
        r.confirmed(ticket); assertEquals(1,f.restored); assertEquals(metadata,f.current!!.metadata)
        fails { r.confirmed(ticket) }; assertEquals(1,f.restored)
    }
    @Test fun crossProfileRestoreRequiresVerifiedAndroidUser() {
        val b=store(); val backup=b.create(record(10)); val f=Filesystem(null).apply { users=setOf(0) }
        fails { RootFileCertificateRestorer(f,b).prepare(backup.id) }; assertEquals(0,f.restored)
    }
    @Test fun nonCaBackupCannotBePublishedByRootRestorer() {
        val raw=javaClass.classLoader!!.getResourceAsStream("non-ca.der")!!.use { it.readBytes() }
        val cert=Certificates.parse(raw); assertEquals(-1,cert.basicConstraints)
        val b=store(); val backup=b.create(record().copy(certificate=cert,raw=raw))
        val f=Filesystem(null)
        fails { RootFileCertificateRestorer(f,b).prepare(backup.id) }
        assertEquals(0,f.restored); assertEquals(1,b.list().size)
    }
    @Test fun unsafeBackupMetadataIsRejected() {
        fails { FileMetadata(metadata.header.replace("\t420\t", "\t438\t")) } // group-writable 0666
        fails { FileMetadata(metadata.header.replace("system_data_file:s0", "x;shell")) }
    }
    @Test fun helperCommandsRejectEveryInjectedArgument() {
        val valid=RootCommand.Guard("/data/app/~~a/com.certmanager.android-a/base.apk", "/data/app/~~a/com.certmanager.android-a/lib/arm64/libcertguard.so", "snapshot", record().locator, "-")
        assertTrue(ShellPolicy.script(valid).contains("/system/bin/app_process"))
        listOf(valid.copy(apk="$(id)"), valid.copy(apk="/data/app/../../data/local/base.apk"), valid.copy(library="/data/app/~~a/com.other.app-a/lib/arm64/libcertguard.so"),valid.copy(library="/tmp/x.so"), valid.copy(action="move;id"),
            valid.copy(path="/etc/passwd"), valid.copy(argument="';reboot;'"), valid.copy(fingerprint="00;reboot")).forEach { fails { ShellPolicy.script(it) } }
    }
    private class FakeProcess(private val exit: Int, private val timeout: Boolean=false) : Process() {
        var destroyed=false
        override fun getOutputStream(): OutputStream=ByteArrayOutputStream()
        override fun getInputStream(): InputStream=ByteArrayInputStream(if(exit==0) "0\n".toByteArray() else byteArrayOf())
        override fun getErrorStream(): InputStream=ByteArrayInputStream("denied".toByteArray())
        override fun waitFor()=exit
        override fun waitFor(timeout: Long, unit: TimeUnit)=!this.timeout
        override fun exitValue()=exit
        override fun destroy(){ destroyed=true }
        override fun destroyForcibly(): Process { destroyed=true; return this }
    }
    @Test fun rootAuthorizationDenialReturnsReadOnlyAndCapturesExitCode() {
        val p=FakeProcess(1); val root=RootShell { p }
        assertFalse(root.request()); assertFalse(root.authorized); assertEquals(1,root.log().single().code); assertTrue(p.destroyed)
    }
    @Test fun rootTimeoutKillsProcessAndRecordsTimeoutWithoutAuthorizing() {
        val p=FakeProcess(0,true); val root=RootShell { p }
        assertFalse(root.request()); assertFalse(root.authorized); assertTrue(root.log().single().timedOut); assertTrue(p.destroyed)
    }
    @Test fun movedFileAndRebootReviewAreSeparateFromWarningConfirmation() {
        val r=record(); val entry=CleanupEntry(r.key,r.fingerprint,0,emptyList(),CleanupStatus.FILE_MOVED,"",fileMoved=true,activeRechecked=true)
        val h=CleanupHistory("boot:1",1,listOf(entry),emptySet())
        val scan=ScanInventory(0,emptyList(),setOf(0),listOf(StoreCoverage(r.locator.substringBeforeLast('/'),true)),bootMarker="boot:2")
        assertEquals(true,CleanupVerification.review(h,scan).rebootDetected); assertFalse(h.warningGoneConfirmed)
        assertEquals(listOf(r.key),CleanupVerification.review(h,scan.copy(observations=listOf(r))).reappeared)
        val history=CleanupHistoryStore(File(temporary.newFolder(),"history.properties"))
        history.save(h.copy(warningGoneConfirmed=true)); assertTrue(history.load()!!.warningGoneConfirmed)
        assertTrue(history.load()!!.entries.single().fileMoved)
    }
}
