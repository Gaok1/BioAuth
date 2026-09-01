import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/vault/totp.dart';
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

  /// Two different events, and treating them alike locked the vault every
  /// time it was opened.
  ///
  /// `inactive` means the app lost focus while staying on screen: the
  /// biometric prompt, the notification shade, a permission dialog. Raising
  /// the biometric prompt *is* how the vault unlocks, so locking here meant
  /// tapping "Desbloquear" locked the vault, and the user authenticated their
  /// way back to "O cofre está bloqueado". Same for revealing an item. The
  /// contents are still covered, because iOS takes its app-switcher snapshot
  /// during `inactive` — but covering and forgetting are not the same act.
  ///
  /// `hidden`, `paused` and `detached` mean the app is actually leaving the
  /// foreground, which is when the vault must forget everything it holds.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        setState(() => _shielded = false);
      case AppLifecycleState.inactive:
        setState(() => _shielded = true);
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
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

  /// Scrolls, because everything on it grows with the system font.
  ///
  /// At the largest accessibility text sizes on a small phone the column below
  /// is taller than the screen, and a `Column` that runs out of room does not
  /// shrink to fit: it lays its last children out past the bottom edge, where
  /// they are painted over by the overflow stripes and cannot be tapped. The
  /// child that falls off is "Desbloquear" — so the vault came up barred with
  /// no way past it, which from the outside is a vault that does not render.
  /// Centred while it fits, scrollable once it does not.
  Widget _locked() => LayoutBuilder(
    builder: (context, constraints) => SingleChildScrollView(
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: constraints.maxHeight),
        child: _lockedBody(),
      ),
    ),
  );

  Widget _lockedBody() => Center(
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
        // Scrollable, because the box is capped at the screen and the text is
        // not. Cut off, this one loses the paragraph saying the discard takes
        // nothing back that a backup could not restore -- which is the whole
        // reason it is safe to press.
        scrollable: true,
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
            ? Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Text(
                    controller.isEmpty
                        ? 'O cofre está vazio. Toque em + para guardar o '
                              'primeiro item.'
                        : 'Nenhum item corresponde à busca.',
                    textAlign: TextAlign.center,
                  ),
                ),
              )
            : ListView.builder(
                itemCount: controller.items.length,
                itemBuilder: (context, index) => _item(controller.items[index]),
              ),
      ),
    ],
  );

  Widget _item(VaultItemSummary item) {
    final secret = controller.secretFor(item.id);
    final code = controller.totpFor(item.id);
    return ListTile(
      leading: Icon(switch (item.kind) {
        VaultItemKind.login => Icons.key,
        VaultItemKind.note => Icons.note,
        VaultItemKind.totp => Icons.timer_outlined,
      }),
      title: Text(item.name),
      // A revealed TOTP shows its digits and how long they last — never the
      // seed, which is what `secret` would be for this kind.
      subtitle: code != null
          ? _TotpSubtitle(code: code)
          : Text(secret ?? (item.username.isEmpty ? item.uri : item.username)),
      trailing: Wrap(
        children: [
          IconButton(
            tooltip: secret == null && code == null
                ? 'Revelar com biometria'
                : 'Ocultar',
            onPressed: controller.busy
                ? null
                : secret == null && code == null
                ? () => controller.reveal(item)
                : controller.hide,
            icon: Icon(
              secret == null && code == null
                  ? Icons.visibility
                  : Icons.visibility_off,
            ),
          ),
          IconButton(
            tooltip: controller.isFavourite(item.id)
                ? 'Tirar dos favoritos'
                : 'Marcar como favorito',
            onPressed: () => controller.toggleFavourite(item.id),
            icon: Icon(
              controller.isFavourite(item.id) ? Icons.star : Icons.star_border,
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
        // The name is the user's, so its length is not ours to assume.
        scrollable: true,
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
                DropdownMenuItem(
                  value: VaultItemKind.totp,
                  child: Text('Código TOTP'),
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
                labelText: switch ((_kind, widget.current)) {
                  (VaultItemKind.totp, _) => 'Chave TOTP ou otpauth://',
                  (_, null) => 'Segredo',
                  _ => 'Novo segredo',
                },
                helperText: _kind == VaultItemKind.totp
                    ? 'Cole a chave que o site mostrou, ou o link do QR code.'
                    : null,
              ),
              // A TOTP seed is pasted from another screen and read back to
              // check it, so hiding it while it is being entered only makes a
              // typo harder to find. It is hidden everywhere afterwards.
              obscureText: _kind != VaultItemKind.totp,
              maxLength: 4096,
              // Rejected here rather than at save time. A seed that will not
              // parse becomes an item that shows an error instead of a code,
              // and by then the user has left the form that could fix it.
              validator: (value) {
                if (value == null || value.isEmpty) return 'Informe o segredo';
                if (_kind != VaultItemKind.totp) return null;
                try {
                  _totpSeed(value);
                  return null;
                } on TotpException catch (failure) {
                  return failure.message;
                }
              },
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
              // A TOTP item stores the seed, never the `otpauth://` URI it may
              // have been pasted as. That URI also carries a label and an
              // issuer, and keeping them would give the item two names that
              // eventually disagree.
              secret: _kind == VaultItemKind.totp
                  ? _totpSeed(_secret.text)
                  : _secret.text,
            ),
          );
        },
        child: const Text('Salvar'),
      ),
    ],
  );
}

/// The six digits and the seconds they have left.
///
/// The countdown is the point: a code with two seconds on it will be rejected
/// by the time it is typed, and a user who cannot see that blames the site.
class _TotpSubtitle extends StatelessWidget {
  const _TotpSubtitle({required this.code});

  final TotpCode code;

  @override
  Widget build(BuildContext context) {
    final remaining = code.secondsRemaining(DateTime.now().toUtc());
    final theme = Theme.of(context);
    return Row(
      children: [
        Text(
          code.digits,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontSize: 18,
            letterSpacing: 3,
          ),
        ),
        const SizedBox(width: 12),
        SizedBox(
          width: 18,
          height: 18,
          child: CircularProgressIndicator(
            value: remaining / totpPeriod.inSeconds,
            strokeWidth: 2,
            // Colour alone would not say "about to expire" to a colour-blind
            // user, so the seconds are written next to it.
            color: remaining <= 5 ? theme.colorScheme.error : null,
          ),
        ),
        const SizedBox(width: 6),
        Text('${remaining}s', style: theme.textTheme.bodySmall),
      ],
    );
  }
}

/// The seed behind whatever the user pasted, in the form an item stores.
///
/// Accepts a bare seed or a whole `otpauth://totp/...`, because both are what
/// sites put on screen next to the QR code, and a form that took only one of
/// them would be a form that rejects half of what people paste.
///
/// Canonical rather than what was pasted, so an item added from a QR link and
/// one typed by hand are the same bytes and a restore does not see them as two
/// accounts. [storedTotpSecret] is what decides the canonical form: base32 for
/// an ordinary seed, and an `otpauth://` URI for one whose digits or window
/// are not the defaults — those used to be parsed off the pasted URI and then
/// thrown away here, which turned an eight-digit or sixty-second issuer into
/// an item that generated confident six-digit codes nothing accepted.
String _totpSeed(String typed) => storedTotpSecret(readTotpSecret(typed));
