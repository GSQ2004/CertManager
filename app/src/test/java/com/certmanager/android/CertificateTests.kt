package com.certmanager.android

import com.certmanager.android.domain.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class CertificateTests {
    @get:Rule val temporary = TemporaryFolder()
    private fun bytes(name: String = "test-ca.der") = javaClass.classLoader!!.getResourceAsStream(name)!!.use { it.readBytes() }
    private fun record(raw: ByteArray = bytes(), user: Int = 0) = CertificateRecord(Certificates.parse(raw), raw,
        CertSource.USER, user, "/data/misc/user/$user/cacerts-added/012345ab.0")
    private fun store() = BackupStore(temporary.newFolder())
    private inline fun fails(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        throw AssertionError("Expected failure")
    }
    @Test fun parsesRealX509PemAndDer() {
        val der = Certificates.parse(bytes()); val pem = Certificates.parse(bytes("test-ca.pem"))
        assertEquals(der.subjectX500Principal, pem.subjectX500Principal)
        assertTrue(der.subjectX500Principal.name.contains("CertManager Unit Test CA"))
        assertTrue(der.basicConstraints >= 0); assertTrue(der.keyUsage[5])
        assertTrue(der.serialNumber.signum() > 0); der.verify(der.publicKey)
    }
    @Test fun rejectsInvalidAndOversizedCertificate() {
        fails { Certificates.parse("not a certificate".toByteArray()) }
        fails { Certificates.parse(ByteArray(MAX_CERT_BYTES + 1)) }
        fails { Certificates.parse(bytes() + byteArrayOf(1, 2, 3)) }
    }
    @Test fun rejectsMultiplePemCertificates() { fails { Certificates.parse(bytes("test-ca.pem") + bytes("test-ca.pem")) } }
    @Test fun fingerprintMatchesIndependentOpenSslValue() {
        assertEquals("74:C9:87:28:A9:EA:F1:55:6E:41:8A:68:B7:E2:B8:0B:B5:48:7C:71:55:7D:38:B4:D1:3C:F9:E3:46:E4:08:97", Certificates.fingerprint(Certificates.parse(bytes()).encoded))
        assertEquals("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", Certificates.digest("abc".toByteArray()))
    }
    @Test fun pemExportRoundTrips() { assertArrayEquals(bytes(), Certificates.parse(Certificates.pem(Certificates.parse(bytes()))).encoded) }
    @Test fun commandParametersAreConstrained() {
        listOf("/data/misc/user/0/cacerts-added;reboot", "' /system", "/system/etc/security/cacerts/..", "$(id)").forEach { path ->
            fails { ShellPolicy.script(RootCommand.ListStore(path)) }
            fails { ShellPolicy.script(RootCommand.ReadCertificate(path)) }
        }
        assertEquals("id -u", ShellPolicy.script(RootCommand.Identity))
        assertTrue(ShellPolicy.script(RootCommand.ReadCertificate(record().locator)).contains("base64"))
        assertFalse(ShellPolicy.script(RootCommand.ReadCertificate(record().locator)).contains("rm "))
    }
    @Test fun certificatePathsRejectTraversalAndInvalidUsers() {
        listOf("/system/etc/security/cacerts/../../build.prop", "/data/misc/user/-1/cacerts-added/012345ab.0",
            "/data/misc/user/00/cacerts-added/012345ab.0", "/data/misc/user/0/cacerts-added/*.0", "/tmp/012345ab.0",
            "/data/misc/user/0/cacerts-added/012345ab.0\nreboot").forEach { assertFalse(it, CertificatePaths.isCertificate(it)) }
        assertTrue(CertificatePaths.isCertificate("/apex/com.android.conscrypt/cacerts/012345ab.10"))
        assertTrue(CertificatePaths.isCertificate("/data/misc_ce/10/cacerts-added/012345ab.0"))
        assertEquals(10, CertificatePaths.userId("/data/misc/user/10/cacerts-added/012345ab.0"))
        assertFalse(CertificatePaths.validLocator(record().copy(userId = 10)))
    }
    @Test fun backupAtomicallyPreservesExactOriginalBytes() {
        val store = store(); val original = record(bytes("test-ca.pem")); val backup = store.create(original)
        val loaded = store.load(backup.id)
        assertArrayEquals(original.raw, loaded.raw); assertEquals(original.fingerprint, loaded.fingerprint)
        assertEquals(original.locator, loaded.locator); assertEquals(0, loaded.userId)
        assertEquals(1, store.list().size)
        assertArrayEquals(original.raw, BackupCodec.decode(store.bytes(backup.id)).raw)
    }
    @Test fun backupDetectsByteAndMetadataTampering() {
        val backup = store().create(record())
        fails { BackupCodec.encode(backup.copy(raw = backup.raw + byteArrayOf(1))) }
        fails { BackupCodec.encode(backup.copy(fingerprint = "00")) }
        val bytes = BackupCodec.encode(backup); bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        fails { BackupCodec.decode(bytes) }
        fails { BackupCodec.decode(BackupCodec.encode(backup) + byteArrayOf(1)) }
    }
    @Test fun backupsRejectPathTraversal() { fails { store().load("../../outside") } }
    @Test fun duplicatesUseCertificateAndAndroidUser() {
        val record = record(); assertTrue(Certificates.duplicate(listOf(record), record.fingerprint, 0))
        assertFalse(Certificates.duplicate(listOf(record), record.fingerprint, 10))
        assertFalse(Certificates.duplicate(listOf(record.copy(source = CertSource.SYSTEM)), record.fingerprint, 0))
    }
    private class Gateway(var record: CertificateRecord?) : TrustGateway {
        var root = true; var direct = true; var failDelete = false; var remains = false; var deletes = 0
        override fun rootAuthorized() = root
        override fun reread(record: CertificateRecord) = this.record
        override fun canUninstall(record: CertificateRecord) = direct
        override fun uninstall(record: CertificateRecord) { deletes++; if (failDelete) error("Denied"); if (!remains) this.record = null }
        override fun installed(fingerprint: String, userId: Int) = record?.let { it.fingerprint == fingerprint && it.userId == userId } == true
    }
    @Test fun deleteRequiresRootBeforeBackup() {
        val record = record(); val gateway = Gateway(record).apply { root = false }; val store = store()
        fails { CertificateOperations(gateway, store).prepareDelete(record) }
        assertTrue(store.list().isEmpty()); assertEquals(0, gateway.deletes)
    }
    @Test fun deleteCannotTargetSystemCa() {
        val record = record().copy(source = CertSource.SYSTEM); val gateway = Gateway(record)
        fails { CertificateOperations(gateway, store()).prepareDelete(record) }; assertEquals(0, gateway.deletes)
    }
    @Test fun deleteCannotProceedWhenBackupFails() {
        val record = record(); val gateway = Gateway(record)
        val file = temporary.newFile()
        fails { CertificateOperations(gateway, BackupStore(file)).prepareDelete(record) }; assertEquals(0, gateway.deletes)
    }
    @Test fun deleteFailuresRetainVerifiedBackup() {
        val record = record(); val gateway = Gateway(record).apply { failDelete = true }; val store = store()
        val ops = CertificateOperations(gateway, store); val ticket = ops.prepareDelete(record)
        assertEquals(0, gateway.deletes) // No delete before explicit confirmation.
        fails { ops.deleteConfirmed(ticket) }; assertArrayEquals(record.raw, store.load(ticket.backupId).raw)
        assertEquals(1, gateway.deletes)
        fails { ops.deleteConfirmed(ticket) }; assertEquals(1, gateway.deletes)
    }
    @Test fun deleteRechecksRootAndBytesAfterConfirmation() {
        val record = record(); val gateway = Gateway(record); val store = store(); val ops = CertificateOperations(gateway, store)
        val ticket = ops.prepareDelete(record); gateway.root = false
        fails { ops.deleteConfirmed(ticket) }; assertEquals(0, gateway.deletes)
        gateway.root = true
        val next = ops.prepareDelete(record)
        gateway.record = record.copy(raw = Certificates.pem(record.certificate))
        fails { ops.deleteConfirmed(next) }; assertEquals(0, gateway.deletes); assertEquals(2, store.list().size)
    }
    @Test fun deletionMustBeObservedAndSettingsFallbackDoesNotMutate() {
        val record = record(); val gateway = Gateway(record).apply { remains = true }; val store = store()
        val ops = CertificateOperations(gateway, store)
        fails { ops.deleteConfirmed(ops.prepareDelete(record)) }; assertEquals(1, store.list().size)
        gateway.direct = false
        assertEquals(DeleteResult.SYSTEM_SETTINGS_REQUIRED, ops.deleteConfirmed(ops.prepareDelete(record)))
        assertEquals(1, gateway.deletes)
    }
    @Test fun successfulDeletionIsVerified() {
        val record = record(); val gateway = Gateway(record); val store = store(); val ops = CertificateOperations(gateway, store)
        assertEquals(DeleteResult.REMOVED, ops.deleteConfirmed(ops.prepareDelete(record)))
        assertEquals(1, store.list().size); assertNull(gateway.record)
    }
    @Test fun restoreFailuresAndCancellationRetainBackup() {
        val record = record(); val gateway = Gateway(null); val store = store(); val backup = store.create(record)
        val ops = CertificateOperations(gateway, store)
        assertArrayEquals(record.certificate.encoded, ops.prepareRestore(backup, emptyList(), 0))
        fails { ops.verifyRestore(backup) }; assertArrayEquals(record.raw, store.load(backup.id).raw)
        gateway.record = record; ops.verifyRestore(backup)
        fails { ops.prepareRestore(backup, listOf(record), 0) }
    }
    @Test fun restoreRejectsCrossProfileAndSystemBackups() {
        val record = record(); val store = store(); val ops = CertificateOperations(Gateway(null), store)
        fails { ops.prepareRestore(store.create(record), emptyList(), 10) }
        fails { ops.prepareRestore(store.create(record.copy(source = CertSource.SYSTEM)), emptyList(), 0) }
    }
    @Test fun corruptedBackupsCannotBeRestored() {
        val record = record(); val store = store(); val backup = store.create(record)
        fails { CertificateOperations(Gateway(null), store).prepareRestore(backup.copy(rawDigest = "invalid"), emptyList(), 0) }
        assertArrayEquals(record.raw, store.load(backup.id).raw)
    }
}
