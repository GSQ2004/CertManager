package com.certmanager.android.domain

import java.io.*
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

data class Backup(val id: String, val createdAt: Long, val source: CertSource, val userId: Int,
                  val locator: String, val fingerprint: String, val rawDigest: String, val raw: ByteArray, val fileMetadata: FileMetadata? = null) {
    val certificate get() = Certificates.parse(raw)
}

object BackupCodec {
    fun encode(backup: Backup): ByteArray {
        validate(backup)
        return ByteArrayOutputStream().also { stream ->
            DataOutputStream(stream).use { out ->
                out.writeUTF("CertManagerBackup/2"); out.writeUTF(backup.id); out.writeLong(backup.createdAt)
                out.writeUTF(backup.source.name); out.writeInt(backup.userId); out.writeUTF(backup.locator)
                out.writeUTF(backup.fingerprint); out.writeUTF(backup.rawDigest)
                out.writeUTF(backup.fileMetadata?.header.orEmpty())
                out.writeInt(backup.raw.size); out.write(backup.raw)
                out.writeUTF(metadataDigest(backup))
            }
        }.toByteArray()
    }
    fun decode(bytes: ByteArray): Backup {
        require(bytes.size <= MAX_CERT_BYTES + 8192) { "Backup too large" }
        return DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val version = input.readUTF()
            require(version in listOf("CertManagerBackup/1", "CertManagerBackup/2")) { "Unknown backup format" }
            val id = input.readUTF(); val date = input.readLong(); val source = CertSource.valueOf(input.readUTF())
            val user = input.readInt(); val path = input.readUTF(); val fingerprint = input.readUTF(); val hash = input.readUTF()
            val metadata = if (version.endsWith("/2")) input.readUTF().ifEmpty { null }?.let(::FileMetadata) else null
            val size = input.readInt(); require(size in 1..MAX_CERT_BYTES)
            val raw = ByteArray(size); input.readFully(raw)
            val backup = Backup(id, date, source, user, path, fingerprint, hash, raw, metadata)
            if (version.endsWith("/2")) require(input.readUTF() == metadataDigest(backup)) { "Backup metadata integrity mismatch" }
            require(input.read() == -1)
            backup.also(::validate)
        }
    }
    private fun metadataDigest(b: Backup): String = Certificates.digest(listOf(b.id, b.createdAt.toString(), b.source.name,
        b.userId.toString(), b.locator, b.fingerprint, b.rawDigest, b.fileMetadata?.header.orEmpty()).joinToString("\u0000").toByteArray(Charsets.UTF_8))
    fun validate(backup: Backup) {
        require(Regex("[a-f0-9-]{36}").matches(backup.id) && UUID.fromString(backup.id).toString() == backup.id)
        require((backup.userId >= 0 || (backup.source == CertSource.MODULE && backup.userId == -1)) && backup.locator.length <= 512)
        require(Certificates.digest(backup.raw) == backup.rawDigest) { "Backup byte integrity mismatch" }
        require(Certificates.fingerprint(Certificates.parse(backup.raw).encoded) == backup.fingerprint) { "Backup fingerprint mismatch" }
    }
}

data class BackupListing(val valid: List<Backup>, val errors: List<String>)

class BackupStore(private val directory: File) {
    private fun file(id: String): File {
        require(UUID.fromString(id).toString() == id)
        return File(directory, "$id.cmb")
    }
    @Synchronized fun create(record: CertificateRecord): Backup {
        check(directory.isDirectory || directory.mkdirs()) { "Cannot create private backup directory" }
        val backup = Backup(UUID.randomUUID().toString(), System.currentTimeMillis(), record.source, record.userId,
            record.locator, record.fingerprint, Certificates.digest(record.raw), record.raw.copyOf(), record.fileMetadata)
        val target = file(backup.id)
        val temp = File.createTempFile("backup-", ".tmp", directory)
        try {
            FileOutputStream(temp).use { it.write(BackupCodec.encode(backup)); it.fd.sync() }
            // Fail closed if this filesystem cannot provide an atomic rename.
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            java.nio.channels.FileChannel.open(directory.toPath(), java.nio.file.StandardOpenOption.READ).use { it.force(true) }
            return load(backup.id).also { check(it.raw.contentEquals(record.raw)) }
        } finally { temp.delete() }
    }
    fun load(id: String): Backup {
        val f = file(id); require(f.length() in 1..(MAX_CERT_BYTES + 8192).toLong())
        return BackupCodec.decode(f.readBytes()).also { require(it.id == id) }
    }
    fun inspect(): BackupListing {
        val errors = mutableListOf<String>()
        val valid = directory.listFiles { f -> f.extension == "cmb" }.orEmpty().mapNotNull { f ->
            try { load(f.nameWithoutExtension) } catch (e: Exception) {
                errors += "Backup integrity check failed: ${f.name} (${e.javaClass.simpleName}); file retained"
                null
            }
        }.sortedByDescending { it.createdAt }
        return BackupListing(valid, errors)
    }
    fun list(): List<Backup> = inspect().let { listing ->
        check(listing.errors.isEmpty()) { listing.errors.joinToString("\n") }; listing.valid
    }
    fun privateFile(id: String): File { load(id); return file(id) }
    fun bytes(id: String): ByteArray = BackupCodec.encode(load(id))
}
