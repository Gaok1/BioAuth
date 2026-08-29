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
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SensitiveContent(
      sensitivity: ContentSensitivity.sensitive,
      child: Scaffold(
        appBar: AppBar(title: const Text('Backup do cofre')),
        body: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            if (_backup case final backup?) ...[
              _CodeCard(backup: backup, onSave: () => _save(backup)),
              const SizedBox(height: 24),
            ],

            Text('Exportar', style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            const Text(
              'Gera um arquivo criptografado com tudo que este cofre guarda, '
              'e um código que só aparece uma vez. Sem o código o arquivo não '
              'serve para nada — inclusive para você.',
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _busy ? null : _export,
              icon: const Icon(Icons.lock_outline),
              label: const Text('Gerar backup'),
            ),

            const Divider(height: 40),

            Text('Restaurar', style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            const Text(
              'Abre um backup e acrescenta o que houver nele. Nada é apagado: '
              'itens que este cofre já tem são ignorados, então restaurar o '
              'mesmo arquivo duas vezes não duplica nada.',
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _restore,
              icon: const Icon(Icons.restore),
              label: const Text('Escolher arquivo…'),
            ),

            const Divider(height: 40),

            Text(
              'Importar de outro gerenciador',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            const Text(
              'Lê uma exportação do Bitwarden (JSON) ou um CSV com cabeçalho. '
              'Você vê o que será adicionado e o que foi recusado antes de '
              'qualquer coisa ser guardada.',
            ),
            const SizedBox(height: 8),
            Text(
              'O arquivo de outro gerenciador está em texto claro. Apague-o do '
              'telefone assim que terminar.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _import,
              icon: const Icon(Icons.download_outlined),
              label: const Text('Escolher exportação…'),
            ),

            if (_message case final message?) ...[
              const SizedBox(height: 20),
              Text(message, style: theme.textTheme.bodyMedium),
            ],
            if (widget.controller.error case final error?) ...[
              const SizedBox(height: 12),
              Text(error, style: TextStyle(color: theme.colorScheme.error)),
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
      setState(() => _message = 'Backup salvo. Guarde o código separado dele.');
    } on Object {
      setState(() => _message = 'Não foi possível salvar o arquivo.');
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
      setState(() => _message = failure.message);
      return;
    } on Object {
      setState(() => _message = 'Não foi possível ler o arquivo.');
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
      setState(() => _message = failure.message);
      return;
    } on Object {
      setState(() => _message = 'Não foi possível ler o arquivo.');
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

  String _describeRestore(VaultRestoreOutcome outcome) {
    if (outcome.added == 0 && outcome.skipped == 0) {
      return 'O backup estava vazio.';
    }
    final added = outcome.added == 1
        ? '1 item restaurado'
        : '${outcome.added} itens restaurados';
    if (outcome.skipped == 0) return '$added.';
    final skipped = outcome.skipped == 1
        ? '1 já estava aqui'
        : '${outcome.skipped} já estavam aqui';
    return '$added; $skipped.';
  }
}

class _CodeCard extends StatelessWidget {
  const _CodeCard({required this.backup, required this.onSave});

  final VaultBackup backup;
  final VoidCallback onSave;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      color: theme.colorScheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Anote este código agora',
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'Ele não aparece de novo, e não fica guardado em lugar nenhum. '
              'Sem ele o backup é um arquivo inútil.',
              style: theme.textTheme.bodySmall,
            ),
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
                // same guarded way a single password is.
                onPressed: () => copySensitive(backup.code),
                icon: const Icon(Icons.copy, size: 18),
                label: const Text('Copiar código'),
              ),
            ),
            const Divider(height: 24),
            Text(
              '${backup.itemCount} itens neste backup.',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            FilledButton.icon(
              onPressed: onSave,
              icon: const Icon(Icons.save_alt),
              label: const Text('Salvar arquivo…'),
            ),
            const SizedBox(height: 8),
            Text(
              'Guarde o arquivo e o código em lugares diferentes. Juntos, os '
              'dois são o cofre inteiro em texto claro.',
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
    return AlertDialog(
      title: const Text('Conferir a importação'),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              preview.items.length == 1
                  ? '1 item será adicionado.'
                  : '${preview.items.length} itens serão adicionados.',
              style: theme.textTheme.bodyLarge,
            ),
            const SizedBox(height: 4),
            Text(
              'Nada é apagado. Itens que este cofre já tem são ignorados.',
              style: theme.textTheme.bodySmall,
            ),
            if (preview.rejections.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(
                preview.rejections.length == 1
                    ? '1 linha não será importada:'
                    : '${preview.rejections.length} linhas não serão importadas:',
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
                          'linha ${rejection.row}'
                          '${rejection.name.isEmpty ? '' : ' (${rejection.name})'}'
                          ' — ${rejection.reason}',
                          style: theme.textTheme.bodySmall,
                        ),
                      ),
                    if (preview.rejections.length > 50)
                      Text(
                        '…e mais ${preview.rejections.length - 50}.',
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
          child: const Text('Cancelar'),
        ),
        FilledButton(
          onPressed: preview.isEmpty
              ? null
              : () => Navigator.of(context).pop(true),
          child: const Text('Importar'),
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
    final created = widget.header.createdAt.toLocal();
    return AlertDialog(
      title: const Text('Código do backup'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '${widget.header.itemCount} itens, de '
            '${created.day.toString().padLeft(2, '0')}/'
            '${created.month.toString().padLeft(2, '0')}/${created.year}.',
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _code,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
            textCapitalization: TextCapitalization.characters,
            decoration: const InputDecoration(
              labelText: 'Código',
              hintText: 'BAV1-…',
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancelar'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_code.text),
          child: const Text('Restaurar'),
        ),
      ],
    );
  }
}
