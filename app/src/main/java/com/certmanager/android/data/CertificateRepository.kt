package com.certmanager.android.data

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Process
import com.certmanager.android.domain.*
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Base64

class CertificateRepository(private val context: Context, val root: RootShell) : CleanupGateway {
    val currentUserId = Process.myUserHandle().hashCode()
    val backups = BackupStore(File(context.noBackupFilesDir, "certificates"))
    private var lastInventory: ScanInventory? = null
    private val rootReasons = mutableMapOf<String, String>()
    val rootFiles = RootFileStore(context, root, backups) { fp, user ->
        val inventory = scanInventory()
        check(inventory.coverage.any { it.location == "/data/misc/user/$user/cacerts-added" && it.readable }) { "Original profile store unreadable" }
        check(inventory.coverage.none { it.location.startsWith("/data/misc/user/$user/cacerts-added/") && !it.readable }) { "Original profile scan incomplete" }
        Certificates.duplicate(inventory.records, fp, user)
    }
    val rootUninstaller = RootFileCertificateUninstaller(rootFiles, backups)
    val rootRestorer = RootFileCertificateRestorer(rootFiles, backups)
    val operations = CertificateOperations(this, backups)
    val cleanupHistory = CleanupHistoryStore(File(context.noBackupFilesDir, "cleanup-history.properties"))
    val cleanup = CleanupCoordinator(this, backups, cleanupHistory)
    private val policy = context.getSystemService(DevicePolicyManager::class.java)
    data class Snapshot(val records: List<CertificateRecord>, val users: Set<Int>, val notes: List<String>, val inventory: ScanInventory)
    private fun keyStore() = KeyStore.getInstance("AndroidCAStore").apply { load(null) }

    private val admin get() = android.content.ComponentName(context, com.certmanager.android.CertAdminReceiver::class.java)
    private fun managesCredentials() = policy.isDeviceOwnerApp(context.packageName) || policy.isProfileOwnerApp(context.packageName)
    private fun credentialBytes(): List<ByteArray> = policy.getInstalledCaCerts(admin)
    fun scan(): Snapshot {
        val inventory = scanInventory()
        val notes = inventory.coverage.filterNot { it.readable }.map { "${it.location}: ${it.detail}" } +
            if (root.authorized) listOf("PARTIAL_VISIBILITY") else listOf("READ_ONLY", "PARTIAL_VISIBILITY")
        return Snapshot(inventory.records, inventory.users, notes, inventory)
    }
    override fun scanInventory(): ScanInventory {
        if (root.authorized) root.verify()
        val observations = mutableListOf<CertificateRecord>()
        val coverage = mutableListOf<StoreCoverage>()
        val users = mutableSetOf(currentUserId)
        val disabled = mutableListOf<DisabledRecord>()
        try {
            val ks = keyStore()
            for (alias in ks.aliases().toList()) {
                val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
                val source = when { alias.startsWith("user:") -> CertSource.USER; alias.startsWith("system:") -> CertSource.SYSTEM; else -> continue }
                observations += CertificateRecord(cert, cert.encoded, source, currentUserId, "keystore:$alias", observedByKeyStore = true)
            }
            coverage += StoreCoverage("keystore:$currentUserId", true)
        } catch (e: Exception) { coverage += StoreCoverage("keystore:$currentUserId", false, e.javaClass.simpleName) }
        if (managesCredentials()) {
            try {
                credentialBytes().forEach { raw ->
                    val cert = Certificates.parse(raw)
                    observations += CertificateRecord(cert, raw, CertSource.USER, currentUserId,
                        "credential:$currentUserId:${Certificates.digest(cert.encoded)}", observedByCredentialService = true)
                }
                coverage += StoreCoverage("credential:$currentUserId", true)
            } catch (e: Exception) { coverage += StoreCoverage("credential:$currentUserId", false, e.javaClass.simpleName) }
        } else coverage += StoreCoverage("credential:$currentUserId", false, "Device/profile owner required for direct KeyChain management API")
        if (root.authorized) {
            val output = root.execute(RootCommand.Users)
            coverage += StoreCoverage("pm list users", output.code == 0, output.error.ifBlank { "Discovery unavailable" })
            if (output.code == 0) Regex("UserInfo\\{([0-9]{1,6}):").findAll(output.output).forEach { users += it.groupValues[1].toInt() }
            val storage = root.execute(RootCommand.UserStorageIds)
            storage.output.lineSequence().filter { Regex("0|[1-9][0-9]{0,5}").matches(it) }.forEach { users += it.toInt() }
            coverage += StoreCoverage("/data/misc/user + /data/misc_ce", storage.code == 0, storage.error)
        }
        val directories = CertificatePaths.systemDirectories + users.flatMap { user ->
            listOf("/data/misc/user/$user/cacerts-added", "/data/misc/user/$user/cacerts-removed",
                "/data/misc_ce/$user/cacerts-added", "/data/misc_ce/$user/cacerts-removed") +
                if (user == 0) listOf("/data/misc/keychain/cacerts-added", "/data/misc/keychain/cacerts-removed") else emptyList()
        }
        fun scanDirectory(dir: String, user: Int) {
            val files = list(dir)
            coverage += StoreCoverage(dir, files != null, if (files == null) "Missing, locked or access denied; not counted as empty" else "")
            files.orEmpty().forEach { name ->
                val path = "$dir/$name"
                if (!CertificatePaths.isCertificate(path)) return@forEach
                try {
                    val raw = read(path)
                    val observation = InventoryFiles.inspect(path, raw, currentUserId)
                    observation.disabled?.let { disabled += it }
                    observation.certificate?.let { observations += it }
                } catch (e: Exception) {
                    coverage += StoreCoverage(path, false, "Read/parse failed: ${e.javaClass.simpleName}")
                    if (dir.endsWith("cacerts-removed")) disabled += DisabledRecord(null, user, path)
                }
            }
        }
        directories.forEach { dir ->
            val user = CertificatePaths.userId("$dir/00000000.0") ?: currentUserId
            scanDirectory(dir, user)
        }
        val modules = mutableListOf<ModuleFinding>()
        if (root.authorized) {
            val ids = root.execute(RootCommand.ModuleIds)
            coverage += StoreCoverage(ModulePaths.ROOT, ids.code == 0, ids.error.ifBlank { "Module discovery unavailable" })
            if (ids.code == 0) ids.output.lineSequence().filter(ModulePaths::validId).forEach { id ->
                val status = root.execute(RootCommand.ModuleStatus(id))
                coverage += StoreCoverage(ModulePaths.root(id), status.code == 0, status.error)
                // Read-only evidence: neither active mount state nor injection is inferred from staging alone.
                ModulePaths.directories(id).forEach { scanDirectory(it, -1) }
                val paths = observations.filter { it.source == CertSource.MODULE && it.locator.startsWith("${ModulePaths.root(id)}/") }.map { it.locator }
                modules += ModuleFinding(id, status.output.contains("DISABLED"), status.output.contains("REMOVAL_PENDING"),
                    status.output.contains("SCRIPT_CA_HINT"), paths)
            }
        } else coverage += StoreCoverage(ModulePaths.ROOT, false, "Root authorization required; custom injection sources may remain undetected")
        val marked = observations.map { record ->
            if (record.source == CertSource.SYSTEM && disabled.any { it.userId == record.userId && it.fingerprint == record.fingerprint })
                record.copy(trust = TrustState.DISABLED) else record
        }
        val boot = runCatching { android.provider.Settings.Global.getInt(context.contentResolver, android.provider.Settings.Global.BOOT_COUNT, -1) }
            .getOrDefault(-1).takeIf { it >= 0 }?.let { "boot-count:$it" }
        return ScanInventory(currentUserId, marked, users, coverage, disabled, modules, boot).also { lastInventory = it }
    }
    private fun list(directory: String): List<String>? {
        require(CertificatePaths.isDirectory(directory))
        val file = File(directory)
        val local = runCatching {
            if (file.canRead() && file.canonicalPath == directory && !java.nio.file.Files.isSymbolicLink(file.toPath()))
                file.list()?.toList() else null
        }.getOrNull()
        if (local != null) return local
        if (!root.authorized) return null
        val r = root.execute(RootCommand.ListStore(directory))
        return if (r.code == 0) r.output.lineSequence().filter { it.isNotBlank() }.toList() else null
    }
    private fun read(path: String): ByteArray? {
        require(CertificatePaths.isCertificate(path))
        val f = File(path)
        val local = runCatching {
            if (!f.canRead() || f.canonicalPath != path || java.nio.file.Files.isSymbolicLink(f.toPath())) return@runCatching null
            require(f.length() in 1..MAX_CERT_BYTES.toLong())
            f.inputStream().use { input ->
                val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer); if (count < 0) break
                    require(out.size() + count <= MAX_CERT_BYTES); out.write(buffer, 0, count)
                }
                out.toByteArray()
            }
        }.getOrNull()
        if (local != null) return local
        if (!root.authorized) return null
        val r = root.execute(RootCommand.ReadCertificate(path))
        return if (r.code == 0) Base64.getMimeDecoder().decode(r.output).also { require(it.size <= MAX_CERT_BYTES) } else null
    }
    override fun rootAuthorized(): Boolean = root.verify()
    override fun reread(record: CertificateRecord): CertificateRecord? {
        require(CertificatePaths.validLocator(record))
        if (record.locator.startsWith("credential:")) {
            check(record.userId == currentUserId) { "Credential API is scoped to the current Android profile" }
            val raw = credentialBytes().firstOrNull { Certificates.fingerprint(Certificates.parse(it).encoded) == record.fingerprint } ?: return null
            return record.copy(certificate = Certificates.parse(raw), raw = raw)
        }
        if (record.locator.startsWith("keystore:")) {
            check(record.userId == currentUserId) { "AndroidCAStore is scoped to the current Android profile" }
            val cert = keyStore().getCertificate(record.locator.removePrefix("keystore:")) as? X509Certificate ?: return null
            return record.copy(certificate = cert, raw = cert.encoded)
        }
        if (RootFilePolicy.eligible(record) && root.authorized && rootFiles.available() && !moduleConflict(record)) {
            val result = runCatching { rootFiles.snapshot(record) }
            if (result.isSuccess) {
                val snapshot = result.getOrNull() ?: return null
                val certificate = Certificates.parse(snapshot.raw)
                return record.copy(certificate = certificate, raw = snapshot.raw, fileMetadata = snapshot.metadata)
            }
            // Unsupported native boundary still permits a read-only byte backup, never file mutation.
            rootReasons[record.key] = result.exceptionOrNull()?.message.orEmpty()
        }
        val raw = read(record.locator) ?: return null
        return record.copy(certificate = Certificates.parse(raw), raw = raw, fileMetadata = null)
    }
    private fun moduleConflict(record: CertificateRecord) = lastInventory?.observations?.any {
        it.source == CertSource.MODULE && it.fingerprint == record.fingerprint
    } == true
    private fun rootEligible(record: CertificateRecord): Boolean {
        if (!root.authorized || !RootFilePolicy.eligible(record) || !rootFiles.available() || moduleConflict(record)) return false
        return runCatching { rootUninstaller.capture(record) }.onFailure { rootReasons[record.key] = it.message.orEmpty() }.isSuccess
    }
    override fun canUninstall(record: CertificateRecord): Boolean = root.authorized && record.source == CertSource.USER &&
        (rootEligible(record) || record.userId == currentUserId &&
            (record.observedByKeyStore || record.observedByCredentialService) && managesCredentials())
    override fun uninstallBlockReason(record: CertificateRecord): String = when {
        record.source != CertSource.USER -> "System/module CA is read-only; excluded from user cleanup"
        !root.authorized -> "Root authorization required; no automatic removal"
        moduleConflict(record) -> "Matching Root module CA found; inspect the module before changing its injected trust"
        RootFilePolicy.eligible(record) -> rootReasons[record.key] ?: "Root helper unavailable or filesystem safety checks not satisfied; use system settings"
        record.userId != currentUserId -> "Open system certificate settings in the original Android profile"
        else -> "Credential service/unknown source: use supported system certificate management"
    }
    override fun uninstall(record: CertificateRecord) {
        check(root.verify()) { "Root authorization lost" }
        require(CertificatePaths.validLocator(record)) { "Invalid certificate source" }
        if (record.fileMetadata != null && RootFilePolicy.eligible(record)) {
            check(rootEligible(record)) { "Root file preflight changed; backup retained; no API fallback" }
            rootUninstaller.uninstall(record)
            return
        }
        check(!RootFilePolicy.eligible(record) || !rootEligible(record)) { "Prepare a verified file metadata backup first" }
        check(record.userId == currentUserId && managesCredentials() &&
            (record.observedByKeyStore || record.observedByCredentialService)) { "System settings required; no unsafe file fallback" }
        val fresh = reread(record) ?: error("Certificate is no longer available")
        check(fresh.fingerprint == record.fingerprint)
        policy.uninstallCaCert(admin, fresh.certificate.encoded)
    }
    override fun installed(fingerprint: String, userId: Int): Boolean {
        check(userId == currentUserId) { "Cannot verify another profile's active trust" }
        val ks = keyStore()
        val inKeyStore = ks.aliases().toList().filter { it.startsWith("user:") }.any { alias ->
            val cert = ks.getCertificate(alias) as? X509Certificate
            cert != null && Certificates.fingerprint(cert.encoded) == fingerprint
        }
        return inKeyStore || (managesCredentials() && credentialBytes().any { Certificates.fingerprint(Certificates.parse(it).encoded) == fingerprint })
    }
    fun checkImport(bytes: ByteArray): X509Certificate {
        val cert = Certificates.parse(bytes)
        require(cert.basicConstraints >= 0) { "Only CA certificates are supported" }
        check(!installed(Certificates.fingerprint(cert.encoded), currentUserId)) { "Certificate already exists" }
        return cert
    }
}
