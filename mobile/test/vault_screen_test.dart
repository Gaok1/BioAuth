import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_screen.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const sensitiveChannel = MethodChannel('flutter/sensitivecontent');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(sensitiveChannel, (call) async => false);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(sensitiveChannel, null);
  });

  testWidgets('protects, unlocks, searches, reveals and locks on background', (
    tester,
  ) async {
    final store = _ScreenStore();
    final controller = VaultController(store: store, copy: (_) async {});
    await tester.pumpWidget(
      MaterialApp(home: VaultScreen(controller: controller)),
    );
    await tester.pumpAndSettle();

    // Sensitivity follows the lock, not the screen's existence. It marks the
    // whole window, and the vault is built on every tab from launch by the
    // `IndexedStack` in the shell -- so registering it unconditionally blacked
    // out the entire app under any screen recording or mirror, from the first
    // frame, forever. A locked vault has nothing on screen to hide.
    expect(find.byType(SensitiveContent), findsNothing);
    expect(find.text('O cofre está bloqueado'), findsOneWidget);
    await tester.tap(find.text('Desbloquear'));
    await tester.pumpAndSettle();
    expect(find.text('Example'), findsOneWidget);
    expect(find.byType(SensitiveContent), findsOneWidget);

    await tester.enterText(find.byType(TextField), 'missing');
    await tester.pump();
    expect(find.text('Nenhum item corresponde à busca.'), findsOneWidget);
    await tester.enterText(find.byType(TextField), 'example');
    await tester.pump();

    await tester.tap(find.byTooltip('Revelar com biometria'));
    await tester.pumpAndSettle();
    expect(find.text('hunter2'), findsOneWidget);
    expect(store.fetches, 1);

    // Losing focus covers the contents without forgetting them. This test
    // used to assert the opposite, which is how the bug survived: raising the
    // biometric prompt costs the app focus, so locking on `inactive` meant
    // every unlock and every reveal locked the vault behind itself.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(controller.locked, isFalse);
    expect(find.byType(ColoredBox), findsWidgets);
    expect(find.text('hunter2'), findsNothing);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(find.text('Example'), findsOneWidget);
  });

  testWidgets('an empty vault invites a first item instead of reporting '
      'nothing found', (tester) async {
    final controller = VaultController(
      store: _ScreenStore(empty: true),
      copy: (_) async {},
    );
    await tester.pumpWidget(
      MaterialApp(home: VaultScreen(controller: controller)),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Desbloquear'));
    await tester.pumpAndSettle();

    // Both states used to say "Nenhum item encontrado.", and to somebody
    // opening a brand new vault that reads as a vault that failed to load --
    // which is exactly what an empty screen behind a fingerprint looks like.
    // The way out of it is the button this sentence points at.
    expect(
      find.text('O cofre está vazio. Toque em + para guardar o primeiro item.'),
      findsOneWidget,
    );
    expect(find.byTooltip('Novo item'), findsOneWidget);
  });

  testWidgets('leaving the foreground locks the vault', (tester) async {
    final store = _ScreenStore();
    final controller = VaultController(store: store, copy: (_) async {});
    await tester.pumpWidget(
      MaterialApp(home: VaultScreen(controller: controller)),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Desbloquear'));
    await tester.pumpAndSettle();
    expect(find.text('Example'), findsOneWidget);

    // The real sequence, which Flutter asserts on: focus goes first, then the
    // views are hidden, and coming back passes through `inactive` again —
    // there is no `hidden` straight to `resumed`. That is also why locking on
    // `inactive` could never be narrowed to "only on the way out": the same
    // event fires on the way back in.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(controller.locked, isFalse, reason: 'losing focus is not leaving');

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    expect(controller.locked, isTrue);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(find.text('O cofre está bloqueado'), findsOneWidget);
    // And the window is recordable again on the way out, not only on the way
    // in: a registration that is never given back is the same permanent
    // blackout by a slower route.
    expect(find.byType(SensitiveContent), findsNothing);
  });
}

class _ScreenStore extends VaultStore {
  _ScreenStore({this.empty = false});

  final bool empty;
  int fetches = 0;
  final item = VaultItemSummary(
    id: 'one',
    revision: 1,
    kind: VaultItemKind.login,
    name: 'Example',
    username: 'alice',
    uri: 'https://example.com',
    updatedAt: DateTime.utc(2026),
  );

  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: empty ? const [] : [item]);

  @override
  Future<VaultSecret> fetch(String id) async {
    fetches++;
    return VaultSecret(id: id, revision: 1, secret: 'hunter2');
  }

  @override
  Future<VaultWrite> create(VaultItemInput item) async =>
      const VaultWrite(id: 'created', revision: 1);
  @override
  Future<VaultWrite> update(
    VaultItemSummary current,
    VaultItemInput item,
  ) async => VaultWrite(id: current.id, revision: current.revision + 1);
  @override
  Future<List<VaultItemSummary>?> delete(VaultItemSummary item) async => null;
}
