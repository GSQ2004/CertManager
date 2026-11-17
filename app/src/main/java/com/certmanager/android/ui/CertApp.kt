package com.certmanager.android.ui

import android.app.Activity
import android.content.SharedPreferences
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.ClipEntry
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.core.content.edit
import com.certmanager.android.R
import com.certmanager.android.domain.*
import java.text.DateFormat
import java.util.Date

private val GreenLight = lightColorScheme(primary = Color(0xFF286B54), secondary = Color(0xFF52645B), tertiary = Color(0xFF3F6374))
private val GreenDark = darkColorScheme(primary = Color(0xFF91D5B6), secondary = Color(0xFFBACCC0), tertiary = Color(0xFFA7CDDF))
private data class Tab(val title: Int, val icon: ImageVector)
private val tabs = listOf(Tab(R.string.home, Icons.Outlined.Home), Tab(R.string.user_certs, Icons.Outlined.Person),
    Tab(R.string.system_certs, Icons.Outlined.Security), Tab(R.string.backups, Icons.Outlined.Inventory2), Tab(R.string.settings, Icons.Outlined.Settings))
private fun date(value: Date): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(value)

@OptIn(ExperimentalMaterial3Api::class)
@Composable fun CertApp(model: CertViewModel, preferences: SharedPreferences, onImport: (Boolean) -> Unit) {
    val state by model.state.collectAsStateWithLifecycle()
    var cleanupPage by rememberSaveable { mutableStateOf(false) }
    var page by rememberSaveable { mutableIntStateOf(0) }
    var theme by rememberSaveable { mutableIntStateOf(preferences.getInt("theme", 0)) }
    var dynamic by rememberSaveable { mutableStateOf(preferences.getBoolean("dynamic", true)) }
    val context = LocalContext.current
    val dark = when (theme) { 1 -> false; 2 -> true; else -> isSystemInDarkTheme() }
    val colors = if (dynamic && Build.VERSION.SDK_INT >= 31) {
        if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else if (dark) GreenDark else GreenLight
    SideEffect {
        (context as? androidx.activity.ComponentActivity)?.enableEdgeToEdge(
            statusBarStyle = androidx.activity.SystemBarStyle.auto(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT) { dark },
            navigationBarStyle = androidx.activity.SystemBarStyle.auto(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT) { dark }
        )
    }
    MaterialTheme(colorScheme = colors) {
        Surface(Modifier.fillMaxSize()) {
            Scaffold(topBar = {
                TopAppBar(title = { Text(if (state.selected != null) stringResource(R.string.details) else if (cleanupPage) stringResource(R.string.cleanup_title) else "CertManager", fontWeight = FontWeight.SemiBold) },
                    navigationIcon = { if (state.selected != null || cleanupPage) IconButton(onClick = { if (state.selected != null) model.select(null) else cleanupPage = false }) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, stringResource(R.string.back)) } },
                    actions = { IconButton(onClick = model::refresh, enabled = !state.loading) { Icon(Icons.Outlined.Refresh, stringResource(R.string.refresh)) } })
            }, bottomBar = {
                NavigationBar {
                    tabs.forEachIndexed { index, tab -> NavigationBarItem(selected = page == index,
                        onClick = { page = index; cleanupPage = false; model.select(null) }, icon = { Icon(tab.icon, null) }, label = { Text(stringResource(tab.title), maxLines = 1) }) }
                }
            }) { padding ->
                Column(Modifier.fillMaxSize().padding(padding)) {
                    if (state.loading) { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(stringResource(R.string.loading), Modifier.padding(horizontal = 20.dp), style = MaterialTheme.typography.labelSmall) }
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        val selected = state.selected
                        if (selected != null) {
                            BackHandler { model.select(null) }
                            CertificateDetail(selected, state.loading, state.rootGranted, model)
                        } else if (cleanupPage) {
                            BackHandler { cleanupPage = false }
                            CleanupScreen(state, model)
                        } else when (page) {
                            0 -> Home(state, model) { cleanupPage = true }
                            1 -> CertificateList(state.records.filter { it.source == CertSource.USER }, false, model, state.loading, state.rootGranted, onImport) { cleanupPage = true }
                            2 -> CertificateList(state.records.filter { it.source == CertSource.SYSTEM }, true, model, state.loading, state.rootGranted, onImport) { cleanupPage = true }
                            3 -> Backups(state, model, onImport)
                            4 -> SettingsPanel(state, model, theme, dynamic, preferences, onTheme = { theme = it; preferences.edit { putInt("theme", it) } }, onDynamic = { dynamic = it; preferences.edit { putBoolean("dynamic", it) } })
                        }
                    }
                }
            }
            CleanupDialogs(state, model)
            state.error?.let { error -> AlertDialog(onDismissRequest = model::clearError,
                title = { Text(stringResource(R.string.error)) }, text = { SelectionContainer { Text(error, Modifier.verticalScroll(rememberScrollState())) } },
                confirmButton = { TextButton(onClick = model::clearError) { Text(stringResource(R.string.close)) } }) }
            state.deleteTicket?.let { ticket -> AlertDialog(onDismissRequest = model::cancelDelete,
                title = { Text(stringResource(R.string.confirm_delete)) }, text = {
                    Text(stringResource(R.string.confirm_delete_body, ticket.backupId, ticket.record.fingerprint,
                        stringResource(if (ticket.direct) R.string.direct_delete else R.string.settings_delete)), Modifier.verticalScroll(rememberScrollState()))
                }, confirmButton = { TextButton(onClick = model::confirmDelete, enabled = !state.loading) { Text(stringResource(R.string.confirm)) } },
                dismissButton = { TextButton(onClick = model::cancelDelete) { Text(stringResource(R.string.cancel)) } }) }
            state.installCandidate?.let { candidate -> AlertDialog(onDismissRequest = model::cancelInstall,
                title = { Text(stringResource(R.string.confirm_install)) }, text = { Text(stringResource(R.string.install_help, candidate.fingerprint), Modifier.verticalScroll(rememberScrollState())) },
                confirmButton = { TextButton(onClick = model::confirmInstall, enabled = !state.loading) { Text(stringResource(R.string.confirm)) } },
                dismissButton = { TextButton(onClick = model::cancelInstall) { Text(stringResource(R.string.cancel)) } }) }
        }
    }
}

@Composable private fun Home(state: UiState, model: CertViewModel, onCleanup: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Icon(Icons.Outlined.VerifiedUser, null, Modifier.size(44.dp), tint = MaterialTheme.colorScheme.primary)
        Text(stringResource(R.string.subtitle), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.android_version, Build.VERSION.RELEASE, Build.VERSION.SDK_INT), color = MaterialTheme.colorScheme.onSurfaceVariant)
        RootCard(state, model)
        Button(onClick = onCleanup, Modifier.fillMaxWidth()) { Text(stringResource(R.string.cleanup_title)) }
        listOf(R.string.user_certs to state.records.count { it.source == CertSource.USER },
            R.string.system_certs to state.records.count { it.source == CertSource.SYSTEM }, R.string.backup_count to state.backups.size).forEach { (label, count) ->
            OutlinedCard(Modifier.fillMaxWidth()) { Row(Modifier.fillMaxWidth().padding(18.dp), horizontalArrangement = Arrangement.SpaceBetween) { Text(stringResource(label)); Text(count.toString(), fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary) } }
        }
        Info(stringResource(R.string.visibility))
        Text(stringResource(R.string.profile, model.repository.currentUserId), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.detected_users, state.users.sorted().joinToString()), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = model::openSettings, Modifier.fillMaxWidth(), enabled = !state.loading) { Text(stringResource(R.string.open_settings)) }
    }
}

@Composable private fun RootCard(state: UiState, model: CertViewModel) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.root_status), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(if (state.rootGranted) R.string.root_granted else if (state.rootRequested) R.string.root_denied else R.string.root_not_requested), fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.root_help), style = MaterialTheme.typography.bodySmall)
            Button(onClick = model::requestRoot, enabled = !state.loading) { Text(stringResource(R.string.request_root)) }
        }
    }
}

@Composable private fun CertificateList(records: List<CertificateRecord>, system: Boolean, model: CertViewModel, busy: Boolean, root: Boolean, onImport: (Boolean) -> Unit, onCleanup: () -> Unit) {
    var query by rememberSaveable(system) { mutableStateOf("") }; var sort by rememberSaveable(system) { mutableIntStateOf(0) }
    var filter by rememberSaveable(system) { mutableIntStateOf(0) }; var user by rememberSaveable(system) { mutableIntStateOf(-1) }
    val users = records.map { it.userId }.distinct().sorted()
    val displayed = remember(records, query, sort, filter, user) {
        records.filter { record ->
            (user < 0 || record.userId == user) &&
                (query.isBlank() || listOf(record.name, record.certificate.issuerX500Principal.name, record.fingerprint,
                    record.fingerprint.replace(":", ""), record.certificate.serialNumber.toString(16)).any { it.contains(query.trim(), true) }) &&
                when (filter) { 1 -> record.valid; 2 -> record.expired; 3 -> record.trust == TrustState.DISABLED; else -> true }
        }.let { list -> when (sort) { 1 -> list.sortedBy { it.certificate.notAfter }; 2 -> list.sortedWith(compareBy({ it.userId }, { it.name })); else -> list.sortedBy { it.name } } }
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text(stringResource(if (system) R.string.system_certs else R.string.user_certs), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold) }
        item { if (system) Info(stringResource(R.string.readonly_help)) else Button(onClick = { onImport(false) }, enabled = !busy && root) { Icon(Icons.Outlined.Add, null); Text(stringResource(R.string.import_cert)) } }
        if (!system) item { OutlinedButton(onClick = onCleanup, enabled = !busy) { Text(stringResource(R.string.cleanup_all)) } }
        item { OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.search)) }, leadingIcon = { Icon(Icons.Outlined.Search, null) }, singleLine = true) }
        item { Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(R.string.filter_all, R.string.filter_valid, R.string.filter_expired, R.string.filter_disabled).forEachIndexed { i, id -> FilterChip(filter == i, { filter = i }, label = { Text(stringResource(id)) }) }
        } }
        item { Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(R.string.sort_name, R.string.sort_expiry, R.string.sort_user).forEachIndexed { i, id -> FilterChip(sort == i, { sort = i }, label = { Text(stringResource(id)) }) }
        } }
        if (users.size > 1) item { Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(user < 0, { user = -1 }, label = { Text(stringResource(R.string.all_users)) })
            users.forEach { id -> FilterChip(user == id, { user = id }, label = { Text(stringResource(R.string.user_id, id)) }) }
        } }
        item { Text(stringResource(R.string.count, displayed.size), style = MaterialTheme.typography.labelMedium) }
        if (displayed.isEmpty()) item { Empty(R.string.empty) }
        items(displayed, key = { it.key }) { record -> CertificateCard(record) { model.select(record) } }
        item { TextButton(onClick = model::openSettings, enabled = !busy) { Text(stringResource(R.string.open_settings)) } }
    }
}

@Composable private fun CertificateCard(record: CertificateRecord, onClick: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text(record.name, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.titleSmall)
            Text(record.certificate.issuerX500Principal.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(stringResource(R.string.valid_until, date(record.certificate.notAfter)), style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.user_id, record.userId), style = MaterialTheme.typography.labelSmall)
                Text(stringResource(if (record.expired) R.string.expired else if (record.valid) R.string.valid else R.string.not_yet_valid), style = MaterialTheme.typography.labelSmall, color = if (record.expired) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
            Text(stringResource(if (record.trust == TrustState.DISABLED) R.string.disabled else if (record.observedByKeyStore) R.string.api_visible else R.string.file_only), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable private fun CertificateDetail(record: CertificateRecord, busy: Boolean, root: Boolean, model: CertViewModel) {
    val certificate = record.certificate
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val usages = listOf("digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly")
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Icon(Icons.Outlined.VerifiedUser, null, Modifier.size(40.dp), tint = MaterialTheme.colorScheme.primary)
        Detail(R.string.subject, record.name); Detail(R.string.issuer, certificate.issuerX500Principal.name)
        Detail(R.string.serial, certificate.serialNumber.toString(16).uppercase())
        Detail(R.string.validity, "${date(certificate.notBefore)}\n→ ${date(certificate.notAfter)}")
        Detail(R.string.fingerprint, record.fingerprint)
        TextButton(onClick = { scope.launch { clipboard.setClipEntry(ClipEntry(android.content.ClipData.newPlainText("SHA-256", record.fingerprint))) }; android.widget.Toast.makeText(context, R.string.copied, android.widget.Toast.LENGTH_SHORT).show() }) { Icon(Icons.Outlined.ContentCopy, null); Spacer(Modifier.width(8.dp)); Text(stringResource(R.string.copy_fingerprint)) }
        Detail(R.string.basic_constraints, if (certificate.basicConstraints < 0) stringResource(R.string.not_ca) else stringResource(R.string.ca_constraint, if (certificate.basicConstraints == Int.MAX_VALUE) "∞" else certificate.basicConstraints.toString()))
        Detail(R.string.key_usage, certificate.keyUsage?.let { bits -> usages.filterIndexed { i, _ -> bits.getOrElse(i) { false } }.joinToString() } ?: stringResource(R.string.not_specified))
        Detail(R.string.signature, "${certificate.sigAlgName}\n${certificate.sigAlgOID}")
        Detail(R.string.source, "${record.source.name} · ${if (record.source == CertSource.MODULE) stringResource(R.string.cleanup_global_module) else stringResource(R.string.user_id, record.userId)}\n${record.origins.joinToString("\n")}")
        Info(stringResource(if (record.trust == TrustState.DISABLED) R.string.disabled else R.string.unknown_trust))
        Button(onClick = { model.backup(record) }, Modifier.fillMaxWidth(), enabled = !busy) { Text(stringResource(R.string.backup)) }
        OutlinedButton(onClick = { model.export(record, false) }, Modifier.fillMaxWidth(), enabled = !busy) { Text(stringResource(R.string.export_original)) }
        OutlinedButton(onClick = { model.export(record, true) }, Modifier.fillMaxWidth(), enabled = !busy) { Text(stringResource(R.string.export_pem)) }
        if (record.source == CertSource.USER) {
            Info(stringResource(R.string.delete_help))
            OutlinedButton(onClick = { model.prepareDelete(record) }, Modifier.fillMaxWidth(), enabled = !busy && root,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text(stringResource(R.string.delete)) }
            if (!root) Text(stringResource(R.string.root_denied), style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = model::openSettings, enabled = !busy) { Text(stringResource(R.string.open_settings)) }
    }
}

@Composable private fun Backups(state: UiState, model: CertViewModel, onImport: (Boolean) -> Unit) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item { Text(stringResource(R.string.backups), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold) }
        item { Info(stringResource(R.string.backup_help)) }
        state.notes.filter { it.startsWith("Backup integrity") }.forEach { note -> item { Info(note) } }
        item { OutlinedButton(onClick = { onImport(true) }, enabled = !state.loading && state.rootGranted) { Text(stringResource(R.string.import_archive)) } }
        if (state.backups.isEmpty()) item { Empty(R.string.empty_backups) }
        items(state.backups, key = { it.id }) { backup ->
            OutlinedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(backup.certificate.subjectX500Principal.name, style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(R.string.backup_date, date(Date(backup.createdAt))), style = MaterialTheme.typography.bodySmall)
                    Text("${backup.source.name} · ${stringResource(R.string.user_id, backup.userId)}", style = MaterialTheme.typography.labelMedium)
                    Detail(R.string.fingerprint, backup.fingerprint); Detail(R.string.backup_integrity, backup.rawDigest)
                    if (backup.source == CertSource.USER) Button(onClick = { model.prepareRestore(backup) }, enabled = !state.loading && state.rootGranted && backup.userId == model.repository.currentUserId) { Text(stringResource(R.string.restore)) }
                    TextButton(onClick = { model.exportBackup(backup, true) }, enabled = !state.loading) { Text(stringResource(R.string.export_backup)) }
                    TextButton(onClick = { model.exportBackup(backup, false) }, enabled = !state.loading) { Text(stringResource(R.string.export_original)) }
                }
            }
        }
    }
}

@Composable private fun SettingsPanel(state: UiState, model: CertViewModel, theme: Int, dynamic: Boolean, preferences: SharedPreferences, onTheme: (Int) -> Unit, onDynamic: (Boolean) -> Unit) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(stringResource(R.string.settings), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.theme), style = MaterialTheme.typography.titleMedium)
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(R.string.theme_system, R.string.theme_light, R.string.theme_dark).forEachIndexed { index, id -> FilterChip(theme == index, { onTheme(index) }, label = { Text(stringResource(id)) }) }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text(stringResource(R.string.dynamic_color), Modifier.weight(1f)); Switch(dynamic, onDynamic, enabled = Build.VERSION.SDK_INT >= 31) }
        Text(stringResource(R.string.language), style = MaterialTheme.typography.titleMedium)
        val selected = preferences.getString("language", "") ?: ""
        listOf("" to stringResource(R.string.language_system), "zh" to "简体中文", "en" to "English").forEach { (code, label) ->
            Row(Modifier.fillMaxWidth().clickable(enabled = !state.loading) { preferences.edit { putString("language", code) }; (context as? Activity)?.recreate() }) {
                RadioButton(selected == code, onClick = null); Text(label, Modifier.padding(12.dp))
            }
        }
        HorizontalDivider(); RootCard(state, model); Info(stringResource(R.string.privacy))
        TextButton(onClick = model::openSettings, enabled = !state.loading) { Text(stringResource(R.string.open_settings)) }
        Text(stringResource(R.string.read_notes), style = MaterialTheme.typography.titleMedium)
        state.notes.filterNot { it == "PARTIAL_VISIBILITY" || it == "READ_ONLY" }.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        Text(stringResource(R.string.visibility), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.root_log), style = MaterialTheme.typography.titleMedium)
        val logs = model.repository.root.log()
        if (logs.isEmpty()) Text(stringResource(R.string.no_logs))
        logs.asReversed().forEach { Text("${date(Date(it.at))} · ${it.operation} · exit=${it.code} · timeout=${it.timedOut}", style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable private fun Detail(label: Int, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        SelectionContainer { Text(value, style = MaterialTheme.typography.bodyMedium) }
    }
}
@Composable private fun Info(text: String) {
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, shape = MaterialTheme.shapes.medium) { Text(text, Modifier.padding(14.dp), style = MaterialTheme.typography.bodySmall) }
}
@Composable private fun Empty(title: Int) {
    Column(Modifier.fillMaxWidth().padding(vertical = 32.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Icon(Icons.Outlined.FolderOpen, null, Modifier.size(36.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.empty_help), style = MaterialTheme.typography.bodySmall)
    }
}
