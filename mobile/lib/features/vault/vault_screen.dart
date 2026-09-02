import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/vault/totp.dart';
import '../../l10n/app_strings.dart';
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

  /// The screen builds in several pieces and each of them needs the words.
  AppStrings get _strings => AppStrings.of(context);

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
  /// tapping unlock locked the vault, and the user authenticated their way
  /// back to a locked vault. Same for revealing an item. The
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

  /// Marks the window unrecordable, and does it without wrapping anything.
  ///
  /// `SensitiveContent` marks the whole *window*, not the subtree it wraps, so
  /// what it encloses is irrelevant to the effect and a zero-sized sibling buys
  /// the same protection. Wrapping the screen with it cost two things that a
  /// sibling does not. It renders `SizedBox.shrink()` until the platform
  /// answers, and re-registers whenever the widget changes, so anything inside
  /// blinks out for a round trip on each change. And it kept the vault's
  /// sensitivity tied to the vault being *built*, which under the
  /// `IndexedStack` in [HomeShell] it always is: every tab, from launch,
  /// whether or not the vault had ever been opened. Under an active media
  /// projection -- a screen recording, a cast, `scrcpy` or any other mirror --
  /// that blacked out the entire app permanently, every other tab along with
  /// it, with nothing on screen to say why.
  ///
  /// Tied to the lock instead, which is when secrets are actually on screen. A
  /// locked vault hides nothing worth hiding.
  Widget _sensitivity() => controller.locked
      ? const SizedBox.shrink()
      : const SensitiveContent(
          sensitivity: ContentSensitivity.sensitive,
          child: SizedBox.shrink(),
        );

  @override
  Widget build(BuildContext context) => Stack(
    children: [
      _shielded
          ? const ColoredBox(color: Colors.black, child: SizedBox.expand())
          : Scaffold(
              appBar: AppBar(
                title: Text(_strings.tabVault),
                actions: [
                  if (!controller.locked) ...[
                    IconButton(
                      tooltip: _strings.vaultRefresh,
                      onPressed: controller.busy ? null : controller.refresh,
                      icon: const Icon(Icons.refresh),
                    ),
                    IconButton(
                      tooltip: _strings.vaultBackup,
                      onPressed: _backup,
                      icon: const Icon(Icons.backup_outlined),
                    ),
                    IconButton(
                      tooltip: _strings.vaultLock,
                      onPressed: controller.lock,
                      icon: const Icon(Icons.lock_outline),
                    ),
                  ],
                ],
              ),
              floatingActionButton: controller.locked
                  ? null
                  : FloatingActionButton(
                      tooltip: _strings.vaultNewItem,
                      onPressed: () => _edit(),
                      child: const Icon(Icons.add),
                    ),
              body: controller.locked ? _locked() : _unlocked(),
            ),
      _sensitivity(),
    ],
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
          Text(
            _strings.vaultLocked,
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 20),
          // Hidden once the failure is one no unlock can fix. Leaving the
          // button there invites the user to keep tapping something that
          // cannot work.
          if (!controller.unrecoverable)
            FilledButton.icon(
              onPressed: controller.busy ? null : controller.unlock,
              icon: const Icon(Icons.fingerprint),
              label: Text(_strings.vaultUnlock),
            ),
          if (controller.failure case final failure?) ...[
            const SizedBox(height: 12),
            Text(
              _strings.vaultFailure(failure),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
          if (controller.canDiscard) ...[
            const SizedBox(height: 20),
            Text(_strings.vaultDiscardNote, textAlign: TextAlign.center),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: controller.busy ? null : _discard,
              icon: const Icon(Icons.delete_forever_outlined),
              label: Text(_strings.vaultDiscardAndRestart),
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
        title: Text(_strings.vaultDiscardTitle),
        content: Text(_strings.vaultDiscardBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(_strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(_strings.vaultDiscard),
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
          decoration: InputDecoration(
            hintText: _strings.vaultSearchHint,
            prefixIcon: const Icon(Icons.search),
            border: const OutlineInputBorder(
              borderRadius: BorderRadius.all(Radius.circular(28)),
            ),
            contentPadding: const EdgeInsets.symmetric(
              vertical: 14,
              horizontal: 16,
            ),
          ),
        ),
      ),
      // Not an error, so not painted as one: nothing failed and nothing was
      // lost. It says the list is older than the vault, which is the only
      // way the user learns that a password created on the PC arrived.
      if (controller.stale)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
          child: Row(
            children: [
              const Icon(Icons.sync_problem_outlined, size: 20),
              const SizedBox(width: 8),
              Expanded(child: Text(_strings.vaultStale)),
              TextButton(
                onPressed: controller.busy ? null : controller.refresh,
                child: Text(_strings.vaultRefreshAction),
              ),
            ],
          ),
        ),
      if (controller.failure case final failure?)
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            _strings.vaultFailure(failure),
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        ),
      // Not styled as an error and not a dialog: it is the answer to "did that
      // work", and it stays until the next action rather than timing out,
      // because a confirmation that has already faded is one the user is
      // reading the list to look for.
      if (controller.notice case final message?)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
          child: Row(
            children: [
              Icon(
                Icons.check_circle_outline,
                size: 18,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Expanded(child: Text(_strings.vaultNotice(message))),
            ],
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
                        ? _strings.vaultEmpty
                        : _strings.vaultNoMatch,
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
                ? _strings.vaultReveal
                : _strings.vaultHide,
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
                ? _strings.vaultUnfavourite
                : _strings.vaultFavourite,
            onPressed: () => controller.toggleFavourite(item.id),
            icon: Icon(
              controller.isFavourite(item.id) ? Icons.star : Icons.star_border,
            ),
          ),
          IconButton(
            tooltip: _strings.vaultCopy,
            onPressed: controller.busy ? null : () => controller.copy(item),
            icon: const Icon(Icons.copy),
          ),
          PopupMenuButton<_ItemAction>(
            onSelected: (action) {
              if (action == _ItemAction.edit) _edit(item);
              if (action == _ItemAction.delete) _delete(item);
            },
            itemBuilder: (_) => [
              PopupMenuItem(
                value: _ItemAction.edit,
                child: Text(_strings.vaultEdit),
              ),
              PopupMenuItem(
                value: _ItemAction.delete,
                child: Text(_strings.vaultDelete),
              ),
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
        title: Text(_strings.vaultDeleteTitle),
        content: Text(_strings.vaultDeleteBody(item.name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(_strings.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(_strings.vaultDelete),
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
  Widget build(BuildContext context) {
    final strings = AppStrings.of(context);
    return AlertDialog(
      title: Text(
        widget.current == null ? strings.vaultNewItem : strings.vaultEditItem,
      ),
      content: Form(
        key: _form,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              DropdownButtonFormField<VaultItemKind>(
                initialValue: _kind,
                decoration: InputDecoration(labelText: strings.vaultKind),
                items: [
                  DropdownMenuItem(
                    value: VaultItemKind.login,
                    child: Text(strings.vaultKindLogin),
                  ),
                  DropdownMenuItem(
                    value: VaultItemKind.note,
                    child: Text(strings.vaultKindNote),
                  ),
                  DropdownMenuItem(
                    value: VaultItemKind.totp,
                    child: Text(strings.vaultKindTotp),
                  ),
                ],
                onChanged: (value) => setState(() => _kind = value!),
              ),
              TextFormField(
                controller: _name,
                decoration: InputDecoration(labelText: strings.vaultName),
                maxLength: 255,
                validator: (value) => value == null || value.trim().isEmpty
                    ? strings.vaultNameRequired
                    : null,
              ),
              TextFormField(
                controller: _username,
                decoration: InputDecoration(labelText: strings.requestUser),
                maxLength: 255,
              ),
              TextFormField(
                controller: _uri,
                decoration: InputDecoration(labelText: strings.vaultAddress),
                maxLength: 1024,
              ),
              TextFormField(
                controller: _secret,
                decoration: InputDecoration(
                  labelText: switch ((_kind, widget.current)) {
                    (VaultItemKind.totp, _) => strings.vaultTotpKey,
                    (_, null) => strings.vaultSecret,
                    _ => strings.vaultNewSecret,
                  },
                  helperText: _kind == VaultItemKind.totp
                      ? strings.vaultTotpHint
                      : null,
                ),
                // A TOTP seed is pasted from another screen and read back to
                // check it, so hiding it while it is being entered only makes
                // a typo harder to find. It is hidden everywhere afterwards.
                obscureText: _kind != VaultItemKind.totp,
                maxLength: 4096,
                // Rejected here rather than at save time. A seed that will not
                // parse becomes an item that shows an error instead of a code,
                // and by then the user has left the form that could fix it.
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return strings.vaultSecretRequired;
                  }
                  if (_kind != VaultItemKind.totp) return null;
                  try {
                    _totpSeed(value);
                    return null;
                  } on TotpException catch (failure) {
                    return strings.totpProblem(failure.problem);
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
          child: Text(strings.cancel),
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
                // A TOTP item stores the seed, never the `otpauth://` URI it
                // may have been pasted as. That URI also carries a label and
                // an issuer, and keeping them would give the item two names
                // that eventually disagree.
                secret: _kind == VaultItemKind.totp
                    ? _totpSeed(_secret.text)
                    : _secret.text,
              ),
            );
          },
          child: Text(strings.save),
        ),
      ],
    );
  }
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
