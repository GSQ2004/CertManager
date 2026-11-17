package com.certmanager.android.domain

/** No caller can provide a shell script. The root transport accepts this closed set only. */
sealed interface RootCommand {
    data object Identity : RootCommand
    data object Users : RootCommand
    data object UserStorageIds : RootCommand
    data object ModuleIds : RootCommand
    data class ModuleStatus(val id: String) : RootCommand
    data class ListStore(val directory: String) : RootCommand
    data class ReadCertificate(val path: String) : RootCommand
}

object CertificatePaths {
    val systemDirectories = listOf("/system/etc/security/cacerts", "/apex/com.android.conscrypt/cacerts")
    private val userDirectory = Regex("/data/misc/user/(0|[1-9][0-9]{0,5})/cacerts-(added|removed)")
    private val ceDirectory = Regex("/data/misc_ce/(0|[1-9][0-9]{0,5})/cacerts-(added|removed)")
    private val name = Regex("[0-9a-fA-F]{8}\\.[0-9]{1,4}")
    fun isDirectory(path: String): Boolean = path in systemDirectories || ModulePaths.isDirectory(path) ||
        path in listOf("/data/misc/keychain/cacerts-added", "/data/misc/keychain/cacerts-removed") ||
        userDirectory.matches(path) || ceDirectory.matches(path)
    fun isCertificate(path: String): Boolean = isDirectory(path.substringBeforeLast('/', "")) &&
        (name.matches(path.substringAfterLast('/')) || (ModulePaths.isDirectory(path.substringBeforeLast('/')) &&
            Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\\.(pem|der|crt|cer)").matches(path.substringAfterLast('/')))) && !path.contains("..")
    fun userId(path: String): Int? = when {
        path.startsWith("/data/misc/keychain/") -> 0
        userDirectory.matches(path.substringBeforeLast('/')) -> path.split('/')[4].toInt()
        ceDirectory.matches(path.substringBeforeLast('/')) -> path.split('/')[3].toInt()
        else -> null
    }
    fun validLocator(record: CertificateRecord): Boolean {
        if (record.locator.startsWith("credential:")) {
            return record.source == CertSource.USER && record.userId >= 0 &&
                Regex("credential:${record.userId}:[0-9A-F]{64}").matches(record.locator)
        }
        if (record.locator.startsWith("keystore:")) {
            if (record.source == CertSource.MODULE) return false
            val alias = record.locator.removePrefix("keystore:")
            return record.userId >= 0 && alias.startsWith(if (record.source == CertSource.USER) "user:" else "system:") &&
                alias.length <= 300 && alias.none { it.isISOControl() }
        }
        if (!isCertificate(record.locator)) return false
        val directory = record.locator.substringBeforeLast('/')
        return when (record.source) {
            CertSource.SYSTEM -> directory in systemDirectories
            CertSource.USER -> userId(record.locator) == record.userId && directory.endsWith("cacerts-added")
            CertSource.MODULE -> ModulePaths.isDirectory(directory) && record.userId == -1
        }
    }
}

object ShellPolicy {
    fun script(command: RootCommand): String = when (command) {
        RootCommand.Identity -> "id -u"
        RootCommand.Users -> "pm list users"
        RootCommand.UserStorageIds -> "ls -1 /data/misc/user /data/misc_ce"
        RootCommand.ModuleIds -> "[ ! -L /data/adb/modules ] && [ \"\$(readlink -f /data/adb/modules)\" = /data/adb/modules ] && ls -1 /data/adb/modules"
        is RootCommand.ModuleStatus -> {
            val p = "'${ModulePaths.root(command.id)}'"
            val hints = listOf("post-fs-data.sh", "service.sh", "post-mount.sh", "boot-completed.sh").joinToString("; ") { script ->
                "[ ! -L $p/$script ] && [ -f $p/$script ] && [ \"\$(stat -c %s $p/$script)\" -le 1048576 ] && " +
                    "grep -qiE 'cacerts|conscrypt|user.?cert|certificate' $p/$script && echo SCRIPT_CA_HINT"
            }
            "[ ! -L $p ] && [ \"\$(readlink -f $p)\" = $p ] && [ -d $p ] || exit 1; " +
                "[ -f $p/disable ] && echo DISABLED; [ -f $p/remove ] && echo REMOVAL_PENDING; $hints; echo CHECKED"
        }
        is RootCommand.ListStore -> {
            require(CertificatePaths.isDirectory(command.directory)) { "Unapproved store" }
            // Reject store symlinks and verify canonical resolution; the script never mutates files.
            val p = "'${command.directory}'"
            "[ ! -L $p ] && [ \"\$(readlink -f $p)\" = $p ] && ls -1 $p"
        }
        is RootCommand.ReadCertificate -> {
            require(CertificatePaths.isCertificate(command.path)) { "Unapproved certificate path" }
            val p = "'${command.path}'"
            "[ ! -L $p ] && [ \"\$(readlink -f $p)\" = $p ] && [ -f $p ] && " +
                "[ \"\$(stat -c %s $p)\" -le $MAX_CERT_BYTES ] && base64 $p"
        }
    }
}
