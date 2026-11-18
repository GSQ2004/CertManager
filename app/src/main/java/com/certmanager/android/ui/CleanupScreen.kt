package com.certmanager.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.certmanager.android.R
import com.certmanager.android.domain.*

@Composable internal fun CleanupScreen(state: UiState, model: CertViewModel) {
    val scan = state.inventory
    val users = scan?.userCertificates.orEmpty()
    var diagnostics by rememberSaveable { mutableStateOf(false) }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Text(stringResource(R.string.cleanup_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.cleanup_scope), style = MaterialTheme.typography.bodySmall)
        }
        item { Notice(stringResource(R.string.cleanup_warning_rule)) }
        item { Text(stringResource(R.string.cleanup_counts, users.size, state.safeCleanupKeys.size, users.size - state.safeCleanupKeys.size), style = MaterialTheme.typography.titleMedium) }
        item { Text(stringResource(R.string.cleanup_users, users.groupingBy { it.userId }.eachCount().toSortedMap().entries.joinToString { "${it.key}: ${it.value}" }.ifEmpty { "—" })) }
        if (!state.rootGranted) item {
            Text(stringResource(R.string.root_denied)); Button(onClick = model::requestRoot, enabled = !state.loading) { Text(stringResource(R.string.request_root)) }
        }
        item {
            Button(onClick = model::showCleanupWarning, enabled = !state.loading && state.rootGranted && users.isNotEmpty(), modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.cleanup_all)) }
            OutlinedButton(onClick = model::refresh, enabled = !state.loading, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.cleanup_scan)) }
            TextButton(onClick = model::openSettings, enabled = !state.loading) { Text(stringResource(R.string.open_settings)) }
        }
        state.cleanupProgress?.let { progress -> item {
            val label = when (progress.phase) {
                CleanupPhase.SCAN -> R.string.cleanup_phase_scan; CleanupPhase.BACKUP -> R.string.cleanup_phase_backup
                CleanupPhase.PREFLIGHT -> R.string.cleanup_phase_preflight; CleanupPhase.DELETE -> R.string.cleanup_phase_delete
                CleanupPhase.VERIFY -> R.string.cleanup_phase_verify; CleanupPhase.DONE -> R.string.cleanup_phase_done
            }
            Text(stringResource(label))
            if (progress.total > 0) {
                LinearProgressIndicator(progress = { progress.completed.toFloat() / progress.total }, modifier = Modifier.fillMaxWidth())
                Text("${progress.completed} / ${progress.total}", style = MaterialTheme.typography.labelSmall)
            }
            Text(stringResource(R.string.cleanup_backup_state, state.backups.size), style = MaterialTheme.typography.bodySmall)
        } }
        state.cleanupHistory?.let { history ->
            item { Text(stringResource(R.string.root_stage_counts, history.entries.sumOf { it.movedFiles }, history.entries.count { it.rebootRechecked })) }
            item { Text(stringResource(if (history.warningGoneConfirmed) R.string.warning_confirmed else R.string.warning_unconfirmed))
                TextButton(onClick = model::confirmWarningGone, enabled = !state.loading) { Text(stringResource(R.string.warning_confirm_action)) }
            }
            item { HorizontalDivider(); Text(stringResource(R.string.cleanup_result), style = MaterialTheme.typography.titleLarge) }
            item { Text(stringResource(R.string.cleanup_result_counts,
                history.entries.count { it.status == CleanupStatus.REMOVED }, history.entries.count { it.status == CleanupStatus.SKIPPED },
                history.entries.count { it.status == CleanupStatus.FAILED }, history.entries.count { it.status == CleanupStatus.UNVERIFIED || it.status == CleanupStatus.PENDING })) }
            items(history.entries, key = { "result:${it.key}" }) { entry ->
                OutlinedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(stringResource(statusLabel(entry.status)), fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.user_id, entry.userId))
                        SelectionContainer { Text(entry.fingerprint, style = MaterialTheme.typography.bodySmall) }
                        Text(stringResource(R.string.cleanup_saved_copies, entry.backupIds.size), style = MaterialTheme.typography.labelSmall)
                        if (entry.status == CleanupStatus.SKIPPED) Text(stringResource(R.string.cleanup_manual_reason), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(R.string.root_stages, entry.backupVerified.toString(), entry.fileMoved.toString(), entry.activeRechecked.toString(), entry.rebootRechecked.toString()), style = MaterialTheme.typography.bodySmall)
                        if (entry.reason.isNotBlank()) Text(entry.reason, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        state.cleanupReview?.let { review -> item {
            Text(stringResource(R.string.cleanup_review_counts, review.remaining, review.targetedRemaining.size, review.reappeared.size, review.possibleInjection.size, review.duplicates.size))
            Text(stringResource(when (review.rebootDetected) { true -> R.string.cleanup_reboot_detected; false -> R.string.cleanup_same_boot; null -> R.string.cleanup_boot_unknown }), style = MaterialTheme.typography.bodySmall)
        } }
        item {
            Notice(stringResource(if (users.isEmpty()) R.string.cleanup_empty_warning else R.string.cleanup_restart))
            OutlinedButton(onClick = model::reviewAfterReboot, enabled = !state.loading && state.rootGranted, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.cleanup_review)) }
        }
        item { HorizontalDivider(); Text(stringResource(R.string.user_certs), style = MaterialTheme.typography.titleLarge) }
        items(users, key = { "user:${it.key}" }) { record ->
            CleanupCertificate(record, record.key in state.safeCleanupKeys) { model.select(record) }
        }
        item { HorizontalDivider(); Text(stringResource(R.string.cleanup_modules), style = MaterialTheme.typography.titleLarge); Notice(stringResource(R.string.cleanup_module_help)) }
        items(scan?.modules.orEmpty().filter { it.scriptHint || it.certificatePaths.isNotEmpty() }, key = { "module:${it.id}" }) { module ->
            OutlinedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(module.id, fontWeight = FontWeight.Bold)
                    Text(stringResource(R.string.cleanup_module_state, module.disabled.toString(), module.pendingRemoval.toString(), module.scriptHint.toString(), module.certificatePaths.size), style = MaterialTheme.typography.bodySmall)
                    module.certificatePaths.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
        items(scan?.records.orEmpty().filter { it.source == CertSource.MODULE }, key = { "module-ca:${it.key}" }) { record -> CleanupCertificate(record, false) { model.select(record) } }
        item { Text(stringResource(R.string.cleanup_disabled_count, scan?.disabled?.size ?: 0), style = MaterialTheme.typography.titleMedium) }
        item { TextButton(onClick = { diagnostics = !diagnostics }) { Text(stringResource(R.string.cleanup_coverage)) } }
        if (diagnostics) {
            items(scan?.coverage.orEmpty(), key = { "coverage:${it.location}" }) { coverage ->
                Text("${if (coverage.readable) "✓" else "?"} ${coverage.location}\n${coverage.detail}", style = MaterialTheme.typography.bodySmall)
            }
            items(scan?.disabled.orEmpty(), key = { "disabled:${it.location}" }) { disabled ->
                Text("${disabled.userId} · ${disabled.location}\n${disabled.fingerprint ?: "—"}", style = MaterialTheme.typography.bodySmall)
            }
        }
        items(scan?.duplicates.orEmpty(), key = { "duplicate:${it.fingerprint}" }) { duplicate ->
            Notice(stringResource(R.string.cleanup_duplicate, duplicate.fingerprint, duplicate.userIds.joinToString(), duplicate.locations.joinToString("\n")))
        }
    }
}

@Composable private fun CleanupCertificate(record: CertificateRecord, allowed: Boolean, onClick: () -> Unit) {
    OutlinedCard(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(record.name, style = MaterialTheme.typography.titleSmall)
            Text("Issuer: ${record.certificate.issuerX500Principal.name}", style = MaterialTheme.typography.bodySmall)
            Text(if (record.source == CertSource.MODULE) stringResource(R.string.cleanup_global_module) else stringResource(R.string.user_id, record.userId))
            Text(stringResource(if (allowed) R.string.cleanup_safe else R.string.cleanup_unsafe), color = if (allowed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error)
            SelectionContainer { Text(record.fingerprint, style = MaterialTheme.typography.bodySmall) }
            Text("${record.source.name}\n${record.origins.joinToString("\n")}", style = MaterialTheme.typography.bodySmall)
        }
    }
}
@Composable private fun Notice(text: String) {
    Surface(color = MaterialTheme.colorScheme.surfaceContainerHigh, shape = MaterialTheme.shapes.medium) { Text(text, Modifier.padding(14.dp), style = MaterialTheme.typography.bodySmall) }
}
private fun statusLabel(status: CleanupStatus) = when (status) {
    CleanupStatus.FILE_MOVED -> R.string.root_file_moved
    CleanupStatus.PENDING -> R.string.cleanup_status_pending; CleanupStatus.REMOVED -> R.string.cleanup_status_removed
    CleanupStatus.SKIPPED -> R.string.cleanup_status_skipped; CleanupStatus.FAILED -> R.string.cleanup_status_failed
    CleanupStatus.UNVERIFIED -> R.string.cleanup_status_unverified
}

@Composable internal fun CleanupDialogs(state: UiState, model: CertViewModel) {
    if (state.cleanupWarning) AlertDialog(onDismissRequest = model::dismissCleanupWarning,
        title = { Text(stringResource(R.string.cleanup_first_confirm)) }, text = {
            val users = state.inventory?.userCertificates.orEmpty()
            Text(stringResource(R.string.cleanup_first_body, users.size,
                users.groupingBy { it.userId }.eachCount().toSortedMap().entries.joinToString { "${it.key}: ${it.value}" },
                state.safeCleanupKeys.size, users.size - state.safeCleanupKeys.size), Modifier.verticalScroll(rememberScrollState()))
        }, confirmButton = { TextButton(onClick = model::prepareCleanup, enabled = !state.loading) { Text(stringResource(R.string.cleanup_backup_continue)) } },
        dismissButton = { TextButton(onClick = model::dismissCleanupWarning) { Text(stringResource(R.string.cancel)) } })
    state.cleanupTicket?.let { ticket ->
        var acknowledged by remember(ticket.id) { mutableStateOf(false) }
        AlertDialog(onDismissRequest = model::cancelCleanup,
            title = { Text(stringResource(R.string.cleanup_second_confirm)) }, text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.cleanup_second_body, ticket.backupCount, ticket.targets.size,
                        ticket.targets.count { it.eligible }, ticket.targets.count { !it.eligible }))
                    ticket.targets.forEach { target ->
                        Text("${target.record.userId} · ${target.record.name}\n${target.record.fingerprint}\n${target.record.locator}\n${target.captures.joinToString { it.backupId }}", style = MaterialTheme.typography.bodySmall)
                    }
                    Row { Checkbox(acknowledged, { acknowledged = it }); Text(stringResource(R.string.cleanup_ack), Modifier.padding(top = 12.dp)) }
                }
            }, confirmButton = { TextButton(onClick = model::confirmCleanup, enabled = acknowledged && !state.loading) { Text(stringResource(R.string.cleanup_execute)) } },
            dismissButton = { TextButton(onClick = model::cancelCleanup) { Text(stringResource(R.string.cancel)) } })
    }
}
