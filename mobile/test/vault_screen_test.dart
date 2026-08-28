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

    expect(find.byType(SensitiveContent), findsOneWidget);
    expect(find.text('O cofre está bloqueado'), findsOneWidget);
    await tester.tap(find.text('Desbloquear'));
    await tester.pumpAndSettle();
    expect(find.text('Example'), findsOneWidget);

    await tester.enterText(find.byType(SearchBar), 'missing');
    await tester.pump();
    expect(find.text('Nenhum item encontrado.'), findsOneWidget);
    await tester.enterText(find.byType(SearchBar), 'example');
    await tester.pump();

    await tester.tap(find.byTooltip('Revelar com biometria'));
    await tester.pumpAndSettle();
    expect(find.text('hunter2'), findsOneWidget);
    expect(store.fetches, 1);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(controller.locked, isTrue);
    expect(find.byType(ColoredBox), findsWidgets);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(find.text('O cofre está bloqueado'), findsOneWidget);
  });
}

class _ScreenStore implements VaultStore {
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
  Future<List<VaultItemSummary>> listAll() async => [item];

  @override
  Future<VaultSecret> fetch(String id) async {
    fetches++;
    return VaultSecret(id: id, revision: 1, secret: 'hunter2');
  }

  @override
  Future<void> create(VaultItemInput item) async {}
  @override
  Future<void> update(VaultItemSummary current, VaultItemInput item) async {}
  @override
  Future<void> delete(VaultItemSummary item) async {}
}
