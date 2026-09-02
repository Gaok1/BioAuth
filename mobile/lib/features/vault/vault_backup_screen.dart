/// Backup and restore for the vault.
///
/// Everything else about this vault is bound to one phone on purpose: the
/// Keystore key cannot leave the device, so losing the phone loses what it
/// protects. That is the right default and a terrible only option, so this is
/// the way out — one encrypted file, one code, and a restore that adds rather
/// than replaces.
///
/// The code is shown exactly once and stored nowhere. Keeping it next to the
/// file it opens would make the file plaintext with extra steps, which is why
/// this screen says where to put it rather than offering to remember it.
library;

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/vault/sensitive_clipboard.dart';

import '../../core/vault/vault_export.dart';
import '../../core/vault/vault_import.dart';
import '../../l10n/app_strings.dart';
import 'vault_controller.dart';
import 'vault_store.dart';

class VaultBackupScreen extends StatefulWidget {
  const VaultBackupScreen({required this.controller, super.key});

  final VaultController controller;

  @override
  State<VaultBackupScreen> createState() => _VaultBackupScreenState();
}

class _VaultBackupScreenState extends State<VaultBackupScreen> {
  VaultBackup? _backup;
  String? _message;

  /// The words for the one message line, read at the moment it is written.
  ///
  /// The line holds an answer to what just happened, so it is built when that
  /// happens rather than kept as a code: a message already on screen when the
  /// language changes stays in the language it was written in, and the next
  /// action replaces it.
  AppStrings get _strings => AppStrings.of(context);

  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = AppStrings.of(context);
    return SensitiveContent(
      sensitivity: ContentSensitivity.sensitive,
      child: Scaffold(
        appBar: AppBar(title: Text(strings.backupTitle)),
        body: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (_backup case final backup?) ...[
              _CodeCard(
                backup: backup,
                onSave: () => _save(backup),
                onCopy: () => _copyCode(backup.code),
              ),
              const SizedBox(height: 24),
            ],

            Text(strings.backupExport, style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(strings.backupExportNote),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _busy ? null : _export,
              icon: const Icon(Icons.lock_outline),
              label: Text(strings.backupCreate),
            ),

            const Divider(height: 40),

            Text(strings.backupRestore, style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(strings.backupRestoreNote),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _restore,
              icon: const Icon(Icons.restore),
              label: Text(strings.backupChooseFile),
            ),

            const Divider(height: 40),

            Text(strings.backupImport, style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(strings.backupImportNote),
            const SizedBox(height: 8),
            Text(
              strings.backupImportWarning,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _import,
              icon: const Icon(Icons.download_outlined),
              label: Text(strings.backupChooseExport),
            ),

            if (_message case final message?) ...[
              const SizedBox(height: 20),
              Text(message, style: theme.textTheme.bodyMedium),
            ],
            if (widget.controller.failure case final failure?) ...[
              const SizedBox(height: 12),
              Text(
                strings.vaultFailure(failure),
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _export() async {
    setState(() {
      _busy = true;
      _message = null;
    });
    final backup = await widget.controller.exportBackup();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _backup = backup;
    });
  }

  /// Copies the code that opens the backup, and says which happened.
  ///
  /// The same reasoning as a copied password: nothing on screen changes when
  /// the clipboard takes the value, and `EXTRA_IS_SENSITIVE` suppresses the
  /// preview Android would otherwise raise. Here the stakes are higher -- this
  /// string is the only way back into the file, and a user who believes they
  /// have it saves the backup and closes the screen.
  Future<void> _copyCode(String code) async {
    try {
      await copySensitive(code);
      if (!mounted) return;
      setState(() => _message = _strings.backupCodeCopied);
    } on Object {
      if (!mounted) return;
      setState(() => _message = _strings.backupCodeCopyFailed);
    }
  }

  Future<void> _save(VaultBackup backup) async {
    final location = await getSaveLocation(
      suggestedName: 'bioauth-cofre.bakv',
      acceptedTypeGroups: const [
        XTypeGroup(label: 'Backup BioAuth', extensions: ['bakv']),
      ],
    );
    if (location == null || !mounted) return;
    try {
      await XFile.fromData(
        backup.bytes,
        mimeType: 'application/octet-stream',
      ).saveTo(location.path);
      // Checked after the write, not only before the picker. This was the one
      // `await` in the file whose result was reported without asking whether
      // there was still a screen to report it to, and it is the slowest one
      // here: the bytes are going to whatever the person chose, which can be
      // an SD card or a cloud folder. Leaving the screen while it wrote raised
      // "setState() called after dispose()" -- after the backup had in fact
      // been written, so the error named the wrong thing entirely.
      if (!mounted) return;
      setState(() => _message = _strings.backupSaved);
    } on Object {
      if (!mounted) return;
      setState(() => _message = _strings.backupSaveFailed);
    }
  }

  Future<void> _restore() async {
    final file = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(label: 'Backup BioAuth', extensions: ['bakv']),
      ],
    );
    if (file == null || !mounted) return;

    final Uint8List bytes;
    final VaultExportHeader header;
    try {
      bytes = await file.readAsBytes();
      // Read before asking for anything. The user has to be told what they
      // picked — how many items, from when — before they are asked to type a
      // code, or "restore" is a button whose effect they learn afterwards.
      header = inspectVaultExport(bytes);
    } on VaultExportException catch (failure) {
      // The guard below the block only ever covered the way out through the
      // bottom. These two leave before reaching it, and they are the likely
      // ways out: picking a file that is not a BAV1 backup is what
      // `inspectVaultExport` is there to reject. Reading it is also the wait
      // -- the bytes come from wherever the person pointed -- so leaving the
      // screen while a wrong file is read reported the rejection to a screen
      // that had gone, as "setState() called after dispose()".
      if (!mounted) return;
      setState(() => _message = _strings.backupProblem(failure.problem));
      return;
    } on Object {
      if (!mounted) return;
      setState(() => _message = _strings.backupReadFailed);
      return;
    }
    if (!mounted) return;

    final code = await showDialog<String>(
      context: context,
      builder: (context) => _CodeDialog(header: header),
    );
    if (code == null || !mounted) return;

    setState(() {
      _busy = true;
      _message = null;
    });
    final outcome = await widget.controller.restoreBackup(bytes, code);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _message = outcome == null ? null : _describeRestore(outcome);
    });
  }

  Future<void> _import() async {
    final file = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(
          label: 'Exportação de gerenciador',
          extensions: ['json', 'csv', 'txt'],
        ),
      ],
    );
    if (file == null || !mounted) return;

    final VaultImportPreview preview;
    try {
      preview = await parseVaultImport(await file.readAsBytes());
    } on VaultImportException catch (failure) {
      // Same shape as `_restore`, and the same reason: a Bitwarden export that
      // will not parse is the ordinary outcome here, and it leaves before the
      // guard below.
      if (!mounted) return;
      setState(() => _message = _strings.importProblem(failure.problem));
      return;
    } on Object {
      if (!mounted) return;
      setState(() => _message = _strings.backupReadFailed);
      return;
    }
    if (!mounted) return;

    // Nothing is written until this returns true. An importer that reported
    // "412 imported" after the fact would be an importer whose mistakes the
    // user finds out about from the vault.
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => _ImportPreviewDialog(preview: preview),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _busy = true;
      _message = null;
    });
    final outcome = await widget.controller.importItems(preview.items);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _message = outcome == null ? null : _describeRestore(outcome);
    });
  }

  String _describeRestore(VaultRestoreOutcome outcome) =>
      _strings.backupRestored(outcome.added, outcome.skipped);
}

class _CodeCard extends StatelessWidget {
  const _CodeCard({
    required this.backup,
    required this.onSave,
    required this.onCopy,
  });

  final VaultBackup backup;
  final VoidCallback onSave;

  /// Handed down rather than done here, because the answer belongs on the
  /// screen's one message line and this card has nowhere to put it.
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = AppStrings.of(context);
    return Card(
      color: theme.colorScheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              strings.backupWriteCodeDown,
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            Text(strings.backupCodeShownOnce, style: theme.textTheme.bodySmall),
            const SizedBox(height: 12),
            SelectableText(
              backup.code,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 16,
                letterSpacing: 1.2,
              ),
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                // The code that opens the whole backup, so it is copied the
                // same guarded way a single password is -- and answered for.
                // Unawaited, the clipboard refusing threw into a button
                // callback with nobody catching it: no message, no copy, and
                // the one string that opens this file left only on screen.
                onPressed: onCopy,
                icon: const Icon(Icons.copy, size: 18),
                label: Text(strings.backupCopyCode),
              ),
            ),
            const Divider(height: 24),
            Text(
              strings.backupItemCount(backup.itemCount),
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            FilledButton.icon(
              onPressed: onSave,
              icon: const Icon(Icons.save_alt),
              label: Text(strings.backupSaveFile),
            ),
            const SizedBox(height: 8),
            Text(
              strings.backupKeepApart,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// What an import would do, before it does any of it.
///
/// The rejection list is the half that matters. An importer that only reports
/// its successes leaves the user to discover the missing entries the next time
/// they need one, which is the worst possible moment.
class _ImportPreviewDialog extends StatelessWidget {
  const _ImportPreviewDialog({required this.preview});

  final VaultImportPreview preview;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final strings = AppStrings.of(context);
    return AlertDialog(
      title: Text(strings.importReviewTitle),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              strings.importWillAdd(preview.items.length),
              style: theme.textTheme.bodyLarge,
            ),
            const SizedBox(height: 4),
            Text(
              strings.importNothingDeleted,
              style: theme.textTheme.bodySmall,
            ),
            if (preview.rejections.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(
                strings.importRejectedCount(preview.rejections.length),
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.error,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 6),
              Flexible(
                child: ListView(
                  shrinkWrap: true,
                  children: [
                    for (final rejection in preview.rejections.take(50))
                      Padding(
                        padding: const EdgeInsets.only(bottom: 4),
                        child: Text(
                          strings.importRejectedRow(
                            rejection.row,
                            rejection.name,
                            strings.rowProblem(rejection.reason),
                          ),
                          style: theme.textTheme.bodySmall,
                        ),
                      ),
                    if (preview.rejections.length > 50)
                      Text(
                        strings.importAndMore(preview.rejections.length - 50),
                        style: theme.textTheme.bodySmall,
                      ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: Text(strings.cancel),
        ),
        FilledButton(
          onPressed: preview.isEmpty
              ? null
              : () => Navigator.of(context).pop(true),
          child: Text(strings.importAction),
        ),
      ],
    );
  }
}

/// Asks for the code, after saying what the file it belongs to contains.
class _CodeDialog extends StatefulWidget {
  const _CodeDialog({required this.header});

  final VaultExportHeader header;

  @override
  State<_CodeDialog> createState() => _CodeDialogState();
}

class _CodeDialogState extends State<_CodeDialog> {
  final _code = TextEditingController();

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final strings = AppStrings.of(context);
    final created = widget.header.createdAt.toLocal();
    return AlertDialog(
      // Scrollable, because the keyboard opens over this one. What it takes
      // is the bottom of the dialog, and the bottom of this dialog is the
      // field the keyboard was raised to type into: a code that cannot be
      // reached is a backup that cannot be restored.
      scrollable: true,
      title: Text(strings.backupCodeTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            strings.backupFileSummary(
              widget.header.itemCount,
              '${created.day.toString().padLeft(2, '0')}/'
              '${created.month.toString().padLeft(2, '0')}/'
              '${created.year}',
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _code,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
            textCapitalization: TextCapitalization.characters,
            decoration: InputDecoration(
              labelText: strings.backupCodeLabel,
              hintText: 'BAV1-…',
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(strings.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_code.text),
          child: Text(strings.backupRestoreAction),
        ),
      ],
    );
  }
}
