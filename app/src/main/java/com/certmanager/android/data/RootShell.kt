package com.certmanager.android.data

import com.certmanager.android.domain.RootCommand
import com.certmanager.android.domain.ShellPolicy
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Synchronous bounded transport; repositories call it only on Dispatchers.IO. */
class RootShell(private val spawn: (List<String>) -> Process = { ProcessBuilder(it).start() }) {
    data class Result(val code: Int, val output: String, val error: String, val timedOut: Boolean)
    data class Entry(val at: Long, val operation: String, val code: Int, val timedOut: Boolean)
    private val history = ArrayDeque<Entry>()
    @Volatile var authorized = false
        private set
    fun log(): List<Entry> = synchronized(history) { history.toList() }
    fun available(): Boolean = runCatching {
        val process = spawn(listOf("/system/bin/sh", "-c", "command -v su"))
        try { process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0 } finally { process.destroy() }
    }.getOrDefault(false)
    fun request(): Boolean {
        authorized = false
        authorized = execute(RootCommand.Identity, 30).let { it.code == 0 && it.output.trim() == "0" }
        return authorized
    }
    fun verify(): Boolean {
        if (!authorized) return false
        authorized = execute(RootCommand.Identity, 8).let { it.code == 0 && it.output.trim() == "0" }
        return authorized
    }
    fun execute(command: RootCommand, timeoutSeconds: Long = 8): Result {
        val script = ShellPolicy.script(command) // Validate before starting su.
        if (command != RootCommand.Identity && !authorized) return Result(-1, "", "Root authorization required", false)
        val checkedScript = if (command == RootCommand.Identity) script else "[ \"\$(/system/bin/id -u)\" = 0 ] || exit 126; $script"
        val pool = Executors.newFixedThreadPool(2) { r -> Thread(r, "cert-root-stream").apply { isDaemon = true } }
        var process: Process? = null
        val result = try {
            val p = spawn(listOf("su", "-c", checkedScript)).also { process = it }
            p.outputStream.close()
            fun read(stream: java.io.InputStream, limit: Int): String = stream.use {
                val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                var truncated = false
                while (true) {
                    val count = it.read(buffer); if (count < 0) break
                    if (out.size() + count > limit) { truncated = true; break }
                    out.write(buffer, 0, count)
                }
                check(!truncated) { "Root output limit exceeded" }
                out.toString("UTF-8")
            }
            val stdout = pool.submit<String> { read(p.inputStream, 2_000_000) }
            val stderr = pool.submit<String> { read(p.errorStream, 16_384) }
            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                p.destroyForcibly(); Result(-1, "", "Root command timed out", true)
            } else Result(p.exitValue(), stdout.get(2, TimeUnit.SECONDS), stderr.get(2, TimeUnit.SECONDS), false)
        } catch (e: Exception) { Result(-1, "", e.javaClass.simpleName + ": " + (e.message ?: "su unavailable"), e is java.util.concurrent.TimeoutException) }
        finally { process?.destroy(); pool.shutdownNow() }
        if (result.code == 126 || result.timedOut) authorized = false
        synchronized(history) {
            if (history.size >= 100) history.removeFirst()
            // Only operation kind, time and outcome; no certificate bytes or subject in logs.
            history.addLast(Entry(System.currentTimeMillis(), (if (command is RootCommand.Guard) "Guard:${command.action}" else command.javaClass.simpleName), result.code, result.timedOut))
        }
        return result
    }
}
