/// The screens that decide something, on a small phone at large text.
///
/// Every one of these is a `Column` of prose and buttons whose height is set
/// by the system font and by names a computer chose. A `Column` given less
/// room than it wants does not shrink: it lays its last children out past the
/// bottom edge, paints stripes over them, and stops them hit-testing. What
/// falls off is the end of the column, which is where the buttons are — so the
/// failure is never cosmetic. It is "Desbloquear" out of reach on a vault that
/// will not open, or "Aprovar" out of reach on a request the computer is still
/// waiting for.
///
/// A widget test at the default 800x600 surface never sees it. These are real
/// phone sizes: 320dp is the narrow end of what Android ships, and 2.0 is
/// inside the range Android's font-size and display-size sliders reach.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/ssh/ssh_service.dart';
import 'package:phone_auth/core/vault/vault_approval.dart';
import 'package:phone_auth/features/onboarding/onboarding_screen.dart';
import 'package:phone_auth/features/ssh/ssh_approval_sheet.dart';
import 'package:phone_auth/features/vault/vault_approval_sheet.dart';
import 'package:phone_auth/features/vault/vault_controller.dart';
import 'package:phone_auth/features/vault/vault_screen.dart';
import 'package:phone_auth/features/vault/vault_store.dart';

/// Small and narrow, ordinary, and tall — each at ordinary and at large text.
const _sizes = [Size(320, 640), Size(360, 760), Size(411, 891)];
const _scales = [1.0, 1.3, 2.0];

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

  /// Puts [home] on a screen of [size] with everything scaled by [scale].
  ///
  /// The scaling goes in `MaterialApp.builder` rather than around it, because
  /// `MaterialApp` installs its own `MediaQuery` from the view and would
  /// overwrite one wrapped outside it.
  Future<void> pump(
    WidgetTester tester,
    Widget home,
    Size size,
    double scale,
  ) async {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      ProviderScope(
        child: MaterialApp(
          home: home,
          builder: (context, child) => MediaQuery.withClampedTextScaling(
            minScaleFactor: scale,
            maxScaleFactor: scale,
            child: child!,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  /// Scrolls [finder] into view and taps it.
  ///
  /// Below the fold of a scrollable is somewhere the user can reach. Below the
  /// bottom of a `Column` is not, and that is the difference these tests hold:
  /// an overflow fails the test on its own, reported by the framework.
  Future<void> reach(WidgetTester tester, Finder finder) async {
    expect(finder, findsOneWidget);
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  for (final size in _sizes) {
    for (final scale in _scales) {
      final where = '${size.width.toInt()}x${size.height.toInt()} at $scale';

      testWidgets('the locked vault can be unlocked on $where', (tester) async {
        final controller = VaultController(store: _Store(), copy: (_) async {});
        addTearDown(controller.dispose);
        await pump(tester, VaultScreen(controller: controller), size, scale);

        await reach(tester, find.text('Desbloquear'));
        expect(
          find.text('Conta do banco com um nome comprido'),
          findsOneWidget,
        );
      });

      testWidgets('an unopenable vault can be discarded on $where', (
        tester,
      ) async {
        final controller = VaultController(
          store: _BrokenStore(),
          copy: (_) async {},
        );
        addTearDown(controller.dispose);
        await pump(tester, VaultScreen(controller: controller), size, scale);

        // The tallest this screen ever gets: the failure, the warning about
        // what discarding costs, and two buttons under it.
        await reach(tester, find.text('Desbloquear'));
        await reach(tester, find.text('Descartar e começar de novo'));
        expect(find.text('Descartar o cofre?'), findsOneWidget);
      });

      testWidgets('a vault request can be refused on $where', (tester) async {
        await pump(tester, const _Opener(_Sheet.vault), size, scale);
        await reach(tester, find.text('abrir'));
        await reach(tester, find.text('Recusar'));
        expect(find.text('Recusar'), findsNothing);
      });

      testWidgets('an ssh request can be refused on $where', (tester) async {
        await pump(tester, const _Opener(_Sheet.ssh), size, scale);
        await reach(tester, find.text('abrir'));
        await reach(tester, find.text('Recusar'));
        expect(find.text('Recusar'), findsNothing);
      });

      testWidgets('onboarding can be finished on $where', (tester) async {
        await pump(tester, const OnboardingScreen(), size, scale);
        await tester.ensureVisible(find.text('Começar'));
      });
    }
  }
}

enum _Sheet { vault, ssh }

/// A button that raises one of the approval sheets, the way the app does.
class _Opener extends StatelessWidget {
  const _Opener(this.sheet);

  final _Sheet sheet;

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Builder(
      builder: (context) => TextButton(
        onPressed: () => switch (sheet) {
          _Sheet.vault => showVaultApprovalSheet(
            context,
            const VaultApprovalRequest(
              id: 'request-1',
              verifierName: 'Meu computador de trabalho',
              operation: VaultOperation.read,
              itemName: 'Banco Exemplo',
              username: 'alice',
              uri: 'https://banco.example.com/login',
            ),
          ),
          _Sheet.ssh => showSshApprovalSheet(
            context,
            const SshApprovalRequest(
              id: 'request-1',
              verifierName: 'Meu computador de trabalho',
              user: 'deploy',
              destination: 'SHA256:abc123',
            ),
          ),
        },
        child: const Text('abrir'),
      ),
    ),
  );
}

class _Store extends VaultStore {
  final item = VaultItemSummary(
    id: 'one',
    revision: 1,
    kind: VaultItemKind.login,
    name: 'Conta do banco com um nome comprido',
    username: 'alice@example.com',
    uri: 'https://banco.example.com',
    updatedAt: DateTime.utc(2026),
  );

  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      VaultPage(items: [item]);
  @override
  Future<VaultSecret> fetch(String id) async =>
      VaultSecret(id: id, revision: 1, secret: 'hunter2');
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

/// A vault whose key a new fingerprint invalidated: unopenable, discardable.
class _BrokenStore extends _Store {
  @override
  Future<VaultPage> listPage([String? cursor]) async =>
      throw PlatformException(code: 'key_invalidated');
}
