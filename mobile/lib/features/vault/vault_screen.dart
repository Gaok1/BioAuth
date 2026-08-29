import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'vault_backup_screen.dart';
import 'vault_controller.dart';
import 'vault_store.dart';

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key, this.controller});

  final VaultController? controller;

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> with WidgetsBindingObserver {
  late final VaultController controller =
      widget.controller ?? VaultController();
  bool _shielded = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    controller.addListener(_changed);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      setState(() => _shielded = false);
    } else {
      controller.lock();
      setState(() => _shielded = true);
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    controller.removeListener(_changed);
    if (widget.controller == null) controller.dispose();
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) => SensitiveContent(
    sensitivity: ContentSensitivity.sensitive,
    child: _shielded
        ? const ColoredBox(color: Colors.black, child: SizedBox.expand())
        : Scaffold(
            appBar: AppBar(
              title: const Text('Cofre'),
              actions: [
                if (!controller.locked) ...[
                  IconButton(
                    tooltip: 'Backup do cofre',
                    onPressed: _backup,
                    icon: const Icon(Icons.backup_outlined),
                  ),
                  IconButton(
                    tooltip: 'Bloquear cofre',
                    onPressed: controller.lock,
                    icon: const Icon(Icons.lock_outline),
                  ),
                ],
              ],
            ),
            floatingActionButton: controller.locked
                ? null
                : FloatingActionButton(
                    tooltip: 'Novo item',
                    onPressed: () => _edit(),
                    child: const Icon(Icons.add),
                  ),
            body: controller.locked ? _locked() : _unlocked(),
          ),
  );

  Widget _locked() => Center(
    child: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.lock, size: 56),
          const SizedBox(height: 16),
          const Text(
            'O cofre está bloqueado',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text('Use sua biometria para abrir os itens deste aparelho.'),
          const SizedBox(height: 20),
          // Hidden once the failure is one no unlock can fix. Leaving the
          // button there invites the user to keep tapping something that
          // cannot work.
          if (!controller.unrecoverable)
            FilledButton.icon(
              onPressed: controller.busy ? null : controller.unlock,
              icon: const Icon(Icons.fingerprint),
              label: const Text('Desbloquear'),
            ),
          if (controller.error case final message?) ...[
            const SizedBox(height: 12),
            Text(
              message,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
          if (controller.canDiscard) ...[
            const SizedBox(height: 20),
            const Text(
              'Descartar apaga o cofre deste telefone e começa vazio. Só faça '
              'isso se você tiver um backup — ou se aceitar perder o que '
              'estava aqui, já que ninguém mais consegue abrir.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: controller.busy ? null : _discard,
              icon: const Icon(Icons.delete_forever_outlined),
              label: const Text('Descartar e começar de novo'),
            ),
          ],
        ],
      ),
    ),
  );

  /// The only path to destroying the vault, and it asks twice: once here, and
  /// once by making the user read what is lost.
  Future<void> _discard() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Descartar o cofre?'),
        content: const Text(
          'Todos os itens guardados neste telefone são apagados, junto com a '
          'chave. Isso não tem volta.\n\n'
          'O conteúdo já está inacessível — descartar não perde nada que '
          'ainda desse para recuperar aqui, mas também não recupera nada. Se '
          'você tem um backup, poderá restaurá-lo depois.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancelar'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Descartar'),
          ),
        ],
      ),
    );
    if (confirmed == true) await controller.discard();
  }

  Widget _unlocked() => Column(
    children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
        // A `TextField` rather than a `SearchBar`. The Material widget looks
        // 56 tall and reports a 24-pixel semantics rectangle for the field
        // inside it, and that rectangle is what explore-by-touch and switch
        // access actually aim at — below Android's 48dp minimum. Here the
        // padding is ours, so what the accessibility service is told matches
        // what the eye sees.
        child: TextField(
          onChanged: controller.search,
          textInputAction: TextInputAction.search,
          decoration: const InputDecoration(
            hintText: 'Buscar nome, usuário ou endereço',
            prefixIcon: Icon(Icons.search),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.all(Radius.circular(28)),
            ),
            contentPadding: EdgeInsets.symmetric(vertical: 14, horizontal: 16),
          ),
        ),
      ),
      if (controller.error case final message?)
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            message,
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ),
      if (controller.busy) const LinearProgressIndicator(),
      Expanded(
        child: controller.items.isEmpty
            ? const Center(child: Text('Nenhum item encontrado.'))
            : ListView.builder(
                itemCount: controller.items.length,
                itemBuilder: (context, index) => _item(controller.items[index]),
              ),
      ),
    ],
  );

  Widget _item(VaultItemSummary item) {
    final secret = controller.secretFor(item.id);
    return ListTile(
      leading: Icon(item.kind == VaultItemKind.login ? Icons.key : Icons.note),
      title: Text(item.name),
      subtitle: Text(
        secret ?? (item.username.isEmpty ? item.uri : item.username),
      ),
      trailing: Wrap(
        children: [
          IconButton(
            tooltip: secret == null ? 'Revelar com biometria' : 'Ocultar',
            onPressed: controller.busy
                ? null
                : secret == null
                ? () => controller.reveal(item)
                : controller.hide,
            icon: Icon(
              secret == null ? Icons.visibility : Icons.visibility_off,
            ),
          ),
          IconButton(
            tooltip: 'Copiar com biometria',
            onPressed: controller.busy ? null : () => controller.copy(item),
            icon: const Icon(Icons.copy),
          ),
          PopupMenuButton<_ItemAction>(
            onSelected: (action) {
              if (action == _ItemAction.edit) _edit(item);
              if (action == _ItemAction.delete) _delete(item);
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: _ItemAction.edit, child: Text('Editar')),
              PopupMenuItem(value: _ItemAction.delete, child: Text('Excluir')),
            ],
          ),
        ],
      ),
    );
  }

  /// Only reachable while the vault is unlocked, which is what keeps the
  /// export behind the same biometric everything else here is behind.
  Future<void> _backup() => Navigator.of(context).push(
    MaterialPageRoute<void>(
      builder: (_) => VaultBackupScreen(controller: controller),
    ),
  );

  Future<void> _edit([VaultItemSummary? current]) async {
    final input = await showDialog<VaultItemInput>(
      context: context,
      builder: (_) => _VaultItemDialog(current: current),
    );
    if (input == null) return;
    if (current == null) {
      await controller.create(input);
    } else {
      await controller.update(current, input);
    }
  }

  Future<void> _delete(VaultItemSummary item) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Excluir item?'),
        content: Text('“${item.name}” será removido do cofre.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Excluir'),
          ),
        ],
      ),
    );
    if (confirmed == true) await controller.delete(item);
  }
}

enum _ItemAction { edit, delete }

class _VaultItemDialog extends StatefulWidget {
  const _VaultItemDialog({this.current});

  final VaultItemSummary? current;

  @override
  State<_VaultItemDialog> createState() => _VaultItemDialogState();
}

class _VaultItemDialogState extends State<_VaultItemDialog> {
  final _form = GlobalKey<FormState>();
  late final _name = TextEditingController(text: widget.current?.name);
  late final _username = TextEditingController(text: widget.current?.username);
  late final _uri = TextEditingController(text: widget.current?.uri);
  final _secret = TextEditingController();
  late VaultItemKind _kind = widget.current?.kind ?? VaultItemKind.login;

  @override
  void dispose() {
    _name.dispose();
    _username.dispose();
    _uri.dispose();
    _secret.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.current == null ? 'Novo item' : 'Editar item'),
    content: Form(
      key: _form,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            DropdownButtonFormField<VaultItemKind>(
              initialValue: _kind,
              decoration: const InputDecoration(labelText: 'Tipo'),
              items: const [
                DropdownMenuItem(
                  value: VaultItemKind.login,
                  child: Text('Login'),
                ),
                DropdownMenuItem(
                  value: VaultItemKind.note,
                  child: Text('Nota segura'),
                ),
              ],
              onChanged: (value) => setState(() => _kind = value!),
            ),
            TextFormField(
              controller: _name,
              decoration: const InputDecoration(labelText: 'Nome'),
              maxLength: 255,
              validator: (value) => value == null || value.trim().isEmpty
                  ? 'Informe um nome'
                  : null,
            ),
            TextFormField(
              controller: _username,
              decoration: const InputDecoration(labelText: 'Usuário'),
              maxLength: 255,
            ),
            TextFormField(
              controller: _uri,
              decoration: const InputDecoration(labelText: 'Endereço'),
              maxLength: 1024,
            ),
            TextFormField(
              controller: _secret,
              decoration: InputDecoration(
                labelText: widget.current == null ? 'Segredo' : 'Novo segredo',
              ),
              obscureText: true,
              maxLength: 4096,
              validator: (value) =>
                  value == null || value.isEmpty ? 'Informe o segredo' : null,
            ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancelar'),
      ),
      FilledButton(
        onPressed: () {
          if (!_form.currentState!.validate()) return;
          Navigator.pop(
            context,
            VaultItemInput(
              kind: _kind,
              name: _name.text.trim(),
              username: _username.text,
              uri: _uri.text,
              secret: _secret.text,
            ),
          );
        },
        child: const Text('Salvar'),
      ),
    ],
  );
}
