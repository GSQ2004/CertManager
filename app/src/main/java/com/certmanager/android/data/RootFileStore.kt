package com.certmanager.android.data

import android.content.Context
import com.certmanager.android.domain.*
import java.io.File
import java.util.Base64

class RootFileStore(private val context: Context, private val root: RootShell,
    private val backups: BackupStore, private val duplicate: (String, Int) -> Boolean) : RootCertificateFiles {
    private val apk get() = context.applicationInfo.sourceDir
    private val library get() = "${context.applicationInfo.nativeLibraryDir}/libcertguard.so"
    override fun authorized() = root.verify()
    override fun verifiedUsers(): Set<Int> {
        val result = root.execute(RootCommand.Users)
        check(result.code == 0 && !result.timedOut) { "Cannot verify Android users" }
        return Regex("UserInfo\\{([0-9]{1,6}):").findAll(result.output).map { it.groupValues[1].toInt() }.toSet()
    }
    private fun execute(action: String, path: String, argument: String, fingerprint: String = "-"): RootShell.Result {
        val result = root.execute(RootCommand.Guard(apk, library, action, path, argument, fingerprint), 20)
        check(result.code == 0 && !result.timedOut) {
            "Root file-level $action failed (${result.code}, timeout=${result.timedOut}); ${result.error.take(2048)}; backup retained"
        }
        return result
    }
    override fun snapshot(record: CertificateRecord): RootFileSnapshot? {
        require(RootFilePolicy.eligible(record))
        val lines = execute("snapshot", record.locator, "-").output.trim().lines()
        if (lines == listOf("ABSENT")) return null
        check(lines.size == 3 && lines[0] == "SNAPSHOT") { "Invalid privileged helper response" }
        val metadata = FileMetadata(Base64.getDecoder().decode(lines[1]).toString(Charsets.UTF_8))
        val raw = Base64.getDecoder().decode(lines[2]); Certificates.parse(raw)
        return RootFileSnapshot(raw, metadata)
    }
    override fun move(backup: Backup) {
        BackupCodec.validate(backups.load(backup.id))
        check(execute("move", backup.locator, backups.privateFile(backup.id).canonicalPath, backup.fingerprint.replace(":", "")).output.trim() == "MOVED")
    }
    override fun restore(backup: Backup) {
        BackupCodec.validate(backups.load(backup.id))
        check(execute("restore", backup.locator, backups.privateFile(backup.id).canonicalPath, backup.fingerprint.replace(":", "")).output.trim() == "RESTORED")
    }
    override fun duplicates(fingerprint: String, userId: Int) = duplicate(fingerprint, userId)
    fun available(): Boolean = File(library).isFile && RootInstallPaths.validLibrary(apk, library)
}
