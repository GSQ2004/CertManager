package com.certmanager.android

import android.app.admin.DeviceAdminReceiver
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.security.KeyChain
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import com.certmanager.android.domain.*
import com.certmanager.android.ui.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CertAdminReceiver : DeviceAdminReceiver()

class MainActivity : ComponentActivity() {
    private val model: CertViewModel by viewModels()
    private var export: UiEvent.Export?
        get() = model.externalExport
        set(value) { model.externalExport = value }
    private var installer: InstallCandidate?
        get() = model.externalInstall
        set(value) { model.externalInstall = value }
    private var checkingDelete: CertificateRecord?
        get() = model.externalDelete
        set(value) { model.externalDelete = value }
    private var archiveImport: Boolean
        get() = model.archiveImport
        set(value) { model.archiveImport = value }
    private var savingForInstall: Boolean
        get() = model.savingForInstall
        set(value) { model.savingForInstall = value }
    private val preferences by lazy { getSharedPreferences("appearance", MODE_PRIVATE) }

    private val save = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val uri = result.data?.data?.takeIf { result.resultCode == RESULT_OK }
        val item = export; export = null
        val shouldInstall = savingForInstall; savingForInstall = false
        if (uri == null || item == null) {
            if (shouldInstall) { installer = null; model.reportError(getString(R.string.install_cancelled)) }
            else if (uri != null && item == null) model.reportError("Export data was lost after process restart. Please export again.")
        } else lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val output = contentResolver.openOutputStream(uri, "wt") ?: error("Cannot open export destination")
                    output.use { it.write(item.bytes); it.flush() }
                }
                if (shouldInstall) external.launch(securityIntent())
                else android.widget.Toast.makeText(this@MainActivity, R.string.exported, android.widget.Toast.LENGTH_SHORT).show()
            } catch (e: Exception) { model.reportError(e.message ?: "Export failed"); installer = null }
        }
    }
    private val open = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@registerForActivityResult
        val archive = archiveImport
        lifecycleScope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.use { input ->
                        val out = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                        val limit = MAX_CERT_BYTES + if (archive) 8192 else 0
                        while (true) {
                            val count = input.read(buffer); if (count < 0) break
                            require(out.size() + count <= limit) { "Input is too large" }; out.write(buffer, 0, count)
                        }
                        out.toByteArray()
                    } ?: error("Cannot open selected document")
                }
                model.importBytes(bytes, archive)
            } catch (e: Exception) { model.reportError(e.message ?: "Import failed") }
        }
    }
    private val external = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val candidate = installer; installer = null
        if (candidate != null) model.afterInstall(candidate)
        else { val record = checkingDelete; checkingDelete = null; model.afterSettings(record) }
    }
    private fun launchSave(item: UiEvent.Export) {
        export = item
        save.launch(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = item.mime
            putExtra(Intent.EXTRA_TITLE, item.filename)
        })
    }
    private fun securityIntent(): Intent = Intent(Settings.ACTION_SECURITY_SETTINGS)
    private fun settingsIntent(): Intent {
        val trusted = Intent("com.android.settings.TRUSTED_CREDENTIALS")
        return if (trusted.resolveActivity(packageManager) != null) trusted else securityIntent()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        installer?.let { outState.putString("pendingFingerprint", it.fingerprint); outState.putString("pendingBackup", it.backupId) }
        outState.putBoolean("awaitingSave", export != null)
        super.onSaveInstanceState(outState)
    }
    override fun attachBaseContext(newBase: android.content.Context) {
        val language = newBase.getSharedPreferences("appearance", MODE_PRIVATE).getString("language", "") ?: ""
        val configuration = android.content.res.Configuration(newBase.resources.configuration)
        if (language.isNotBlank()) configuration.setLocale(java.util.Locale.forLanguageTag(language))
        super.attachBaseContext(newBase.createConfigurationContext(configuration))
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (installer == null && savedInstanceState?.getString("pendingFingerprint") != null) {
            installer = InstallCandidate(byteArrayOf(), savedInstanceState.getString("pendingFingerprint")!!,
                savedInstanceState.getString("pendingBackup"))
        }
        if (savedInstanceState?.getBoolean("awaitingSave") == true && export == null) {
            installer = null; model.reportError("Pending export interrupted by process restart. Backups retained; please try again.")
        }
        setContent {
            CertApp(model, preferences, onImport = { archive ->
                archiveImport = archive
                open.launch(arrayOf("*/*"))
            })
        }
        lifecycleScope.launch {
            model.events.collect { event ->
                try {
                    when (event) {
                        is UiEvent.Export -> launchSave(event)
                        is UiEvent.Install -> {
                            installer = event.candidate
                            if (Build.VERSION.SDK_INT >= 30) {
                                // Android 11+ requires manual CA installation in Settings.
                                // The user selects a document destination; no broad storage permission or public auto-write.
                                savingForInstall = true
                                launchSave(UiEvent.Export(event.candidate.raw, "CertManager-CA.crt", "application/x-x509-ca-cert"))
                            } else external.launch(KeyChain.createInstallIntent().apply {
                                putExtra(KeyChain.EXTRA_CERTIFICATE, event.candidate.raw)
                                putExtra(KeyChain.EXTRA_NAME, "CertManager CA")
                            })
                        }
                        is UiEvent.Settings -> { checkingDelete = event.record; external.launch(settingsIntent()) }
                        is UiEvent.Message -> {
                            val id = when (event.key) {
                                "backed_up" -> R.string.backed_up; "removed" -> R.string.removed
                                "installed" -> R.string.installed; else -> R.string.done
                            }
                            android.widget.Toast.makeText(this@MainActivity, id, android.widget.Toast.LENGTH_LONG).show()
                        }
                    }
                } catch (e: ActivityNotFoundException) { installer = null; checkingDelete = null; model.reportError(getString(R.string.settings_unavailable)) }
                catch (e: Exception) { model.reportError(e.message ?: "Operation failed") }
            }
        }
    }
}
