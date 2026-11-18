package com.certmanager.android.data

import android.system.Os
import com.certmanager.android.domain.*
import java.io.File
import java.util.Base64

/** Entry point executed by su + app_process from the installed APK, without an exported component. */
object NativeGuard {
    external fun snapshot(path: String): Array<ByteArray>?
    external fun move(path: String, id: String, expected: String, raw: ByteArray)
    external fun restore(path: String, id: String, metadata: String, raw: ByteArray)
}
object RootWorker {
    @JvmStatic fun main(args: Array<String>) {
        try {
            check(Os.getuid() == 0) { "Root required" }
            require(args.size == 5)
            val (library, action, path, argument, expectedFingerprint) = args
            require(RootInstallPaths.validLibrary(library.substringBeforeLast("/lib/") + "/base.apk", library))
            System.load(library)
            require(Regex("/data/misc/user/(0|[1-9][0-9]{0,5})/cacerts-added/[0-9a-f]{8}\\.[0-9]{1,4}").matches(path))
            when (action) {
                "snapshot" -> {
                    require(argument == "-" && expectedFingerprint == "-")
                    val snapshot = NativeGuard.snapshot(path)
                    if (snapshot == null) println("ABSENT") else {
                        Certificates.parse(snapshot[1])
                        FileMetadata(snapshot[0].toString(Charsets.UTF_8))
                        println("SNAPSHOT")
                        snapshot.forEach { println(Base64.getEncoder().encodeToString(it)) }
                    }
                }
                "move", "restore" -> {
                    require(Regex("/data/(?:(?:user|user_de)/[0-9]+|data)/com\\.certmanager\\.android/no_backup/certificates/[0-9a-f-]{36}\\.cmb").matches(argument))
                    val file = File(argument)
                    check(file.canonicalPath == argument && !java.nio.file.Files.isSymbolicLink(file.toPath()))
                    require(file.length() in 1..(MAX_CERT_BYTES + 8192).toLong())
                    val backup = BackupCodec.decode(file.readBytes())
                    require(backup.id == file.nameWithoutExtension && backup.locator == path && backup.source == CertSource.USER)
                    require(Regex("[0-9A-F]{64}").matches(expectedFingerprint) && backup.fingerprint.replace(":", "") == expectedFingerprint) { "Selected fingerprint no longer matches backup" }
                    val metadata = backup.fileMetadata ?: error("Verified file metadata missing")
                    val record = CertificateRecord(backup.certificate, backup.raw, backup.source, backup.userId, backup.locator)
                    require(RootFilePolicy.eligible(record))
                    if (action == "move") NativeGuard.move(path, backup.id, metadata.header, backup.raw)
                    else {
                        require(backup.certificate.basicConstraints >= 0) { "Only CA certificates can be restored" }
                        // Detect DER duplicates even when PEM encodings differ. Any unreadable candidate aborts.
                        val directory = File(path).parentFile!!
                        val names = directory.list() ?: error("Cannot enumerate restore destination")
                        for (name in names.filter { Regex("[0-9a-f]{8}\\.[0-9]{1,4}").matches(it) }) {
                            val raw = NativeGuard.snapshot("${directory.path}/$name")?.get(1) ?: error("Store changed during duplicate check")
                            check(Certificates.fingerprint(Certificates.parse(raw).encoded) != backup.fingerprint) { "Duplicate certificate already exists" }
                        }
                        NativeGuard.restore(path, backup.id, metadata.header, backup.raw)
                    }
                    println(if (action == "move") "MOVED" else "RESTORED")
                }
                else -> error("Unknown operation")
            }
        } catch (error: Throwable) {
            System.err.println("CertGuard: ${error.javaClass.simpleName}: ${error.message}")
            kotlin.system.exitProcess(1)
        }
    }
}
