// Renders the real screens to PNG for the README.
//
// Not a test, and deliberately not named `*_test.dart` so `flutter test` leaves
// it alone. Run it on purpose:
//
//     flutter test test/media/capture_screens.dart
//
// Every image is the actual widget tree the app builds, at phone size, with
// real fonts, showing state the real controller produced — the approval frames
// are captured mid-flight while `AppController.approve` is running, not posed.
// Nothing here is a mockup: if a screen changes, re-running this changes the
// picture, and a picture that no longer matches the app is a failure the next
// run fixes rather than a drawing someone has to redo.
//
// Fonts come from the SDK's bundled Roboto. Without loading them the test
// renderer draws every glyph as a filled box, which reads as a broken app.

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/theme.dart';
import 'package:phone_auth/core/mock/fake_phone_authenticator.dart';
import 'package:phone_auth/core/mock/mock_seed.dart';
import 'package:phone_auth/domain/authentication_request.dart';
import 'package:phone_auth/features/authentication/authentication_request_screen.dart';
import 'package:phone_auth/features/devices/devices_screen.dart';
import 'package:phone_auth/features/history/history_screen.dart';
import 'package:phone_auth/features/security/security_screen.dart';
import 'package:phone_auth/shared/verification_code_panel.dart';

/// Where the READMEs read them from.
const String outputDirectory = '../docs/media';

/// A modern phone in logical pixels, captured at 3x.
const Size phone = Size(390, 844);
const double pixelRatio = 3;

const ValueKey<String> _captureKey = ValueKey('capture');

/// A fixed instant, so a re-run does not rewrite every file with a new clock.
final DateTime capturedAt = DateTime.utc(2026, 8, 26, 21, 14);

void main() {
  setUpAll(_loadRobotoFromSdk);

  testWidgets('captures the screens the README shows', (tester) async {
    for (final brightness in Brightness.values) {
      final suffix = brightness == Brightness.dark ? '-dark' : '';

      var scene = await _open(
        tester,
        brightness,
        const Scaffold(body: SafeArea(child: DevicesScreen())),
      );
      await _shoot(tester, 'devices$suffix');
      scene.dispose();

      scene = await _open(
        tester,
        brightness,
        const AuthenticationRequestScreen(requestId: 'mock-request-1'),
      );
      await _shoot(tester, 'request$suffix');
      scene.dispose();

      scene = await _open(
        tester,
        brightness,
        _centred(
          VerificationCodePanel(
            code: '420017',
            verifierId: 'Desktop-Casa',
            onConfirm: () async {},
            onReject: () async {},
          ),
        ),
      );
      await _shoot(tester, 'pairing-code$suffix');
      scene.dispose();

      scene = await _open(
        tester,
        brightness,
        const Scaffold(body: SafeArea(child: HistoryScreen())),
      );
      await _buildAuditTrail(tester, scene);
      await _shoot(tester, 'history$suffix');
      scene.dispose();

      scene = await _open(tester, brightness, const SecurityScreen());
      await _shoot(tester, 'security$suffix');
      scene.dispose();
    }
  });

  testWidgets('captures an approval as it happens', (tester) async {
    // The frames below are taken while `approve` is in flight. The phases are
    // whatever the controller is actually in at that instant.
    var scene = await _open(
      tester,
      Brightness.light,
      const Scaffold(body: SafeArea(child: DevicesScreen())),
    );
    await _shoot(tester, 'flow/1-request');
    scene.dispose();

    scene = await _open(
      tester,
      Brightness.light,
      const AuthenticationRequestScreen(requestId: 'mock-request-1'),
    );
    await _shoot(tester, 'flow/2-detail');

    final approving = scene.controller.approve('mock-request-1');
    // FakePhoneAuthenticator holds each phase for 150ms.
    await tester.pump(const Duration(milliseconds: 60));
    await _shoot(tester, 'flow/3-biometric');
    await tester.pump(const Duration(milliseconds: 160));
    await _shoot(tester, 'flow/4-signing');
    await approving;
    await tester.pumpAndSettle();
    scene.dispose();

    scene = await _open(
      tester,
      Brightness.light,
      const Scaffold(body: SafeArea(child: HistoryScreen())),
    );
    await _buildAuditTrail(tester, scene);
    await _shoot(tester, 'flow/5-history');
    scene.dispose();
  });
}

/// One pumped app, with a handle on the controller behind it.
class _Scene {
  _Scene(this.container);

  final ProviderContainer container;

  AppController get controller =>
      container.read(appControllerProvider.notifier);

  void dispose() => container.dispose();
}

/// Pumps [child] inside the real app shell, seeded like the dev flavour.
Future<_Scene> _open(
  WidgetTester tester,
  Brightness brightness,
  Widget child,
) async {
  tester.view.physicalSize = phone * pixelRatio;
  tester.view.devicePixelRatio = pixelRatio;
  addTearDown(tester.view.reset);

  final container = ProviderContainer(
    overrides: [
      appConfigProvider.overrideWithValue(
        AppConfig.development(buildMockSeed(capturedAt)),
      ),
      phoneAuthenticatorProvider.overrideWithValue(
        const FakePhoneAuthenticator(),
      ),
    ],
  );

  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: buildTheme(brightness),
        home: RepaintBoundary(key: _captureKey, child: child),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return _Scene(container);
}

/// Writes whatever is on screen right now.
///
/// The rasterisation runs through [WidgetTester.runAsync]: `toImage` needs the
/// real event loop, and inside the test's fake-async zone its future simply
/// never completes.
Future<void> _shoot(WidgetTester tester, String name) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(
    find.byKey(_captureKey),
  );
  final bytes = await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: pixelRatio);
    final data = await image.toByteData(format: ui.ImageByteFormat.png);
    image.dispose();
    return data;
  });

  final file = File('$outputDirectory/$name.png');
  file.parent.createSync(recursive: true);
  file.writeAsBytesSync(bytes!.buffer.asUint8List());
}

/// Produces a history by actually approving and denying requests.
///
/// Entries written by [AppController] itself, so the timestamps, the wording
/// and the outcomes are the ones a user would see.
Future<void> _buildAuditTrail(WidgetTester tester, _Scene scene) async {
  final controller = scene.controller;

  // Started, then settled, then awaited. The fake authenticator sleeps between
  // phases, and those timers only fire while the test pumps — awaiting first
  // would wait forever on a clock nothing is advancing.
  Future<void> approve(String id) async {
    final approving = controller.approve(id);
    await tester.pumpAndSettle();
    await approving;
  }

  await approve('mock-request-1');

  controller.receive(
    _request(
      id: 'r-2',
      service: 'sudo',
      action: 'nixos-rebuild switch',
      resource: 'Desktop-NixOS',
    ),
  );
  await approve('r-2');

  controller.receive(
    _request(
      id: 'r-3',
      verifierId: 'notebook',
      verifierName: 'Notebook',
      service: 'login',
      action: 'Desbloquear sessão',
      resource: 'console',
    ),
  );
  controller.deny('r-3');
  await tester.pumpAndSettle();
}

AuthenticationRequest _request({
  required String id,
  String verifierId = 'desktop-casa',
  String verifierName = 'Desktop-Casa',
  required String service,
  required String action,
  required String resource,
}) {
  final now = DateTime.now().toUtc();
  return AuthenticationRequest(
    requestId: id,
    verifierId: verifierId,
    verifierName: verifierName,
    credentialId: '$verifierId-authorization-v1',
    challenge: Uint8List.fromList(List<int>.generate(32, (index) => index)),
    origin: 'QrNetworkTransport • pareado',
    service: service,
    action: action,
    resource: resource,
    user: 'alice',
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    sessionBinding: Uint8List.fromList(
      List<int>.generate(32, (index) => 255 - index),
    ),
  );
}

Widget _centred(Widget child) => Scaffold(
  body: SafeArea(
    child: Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: child,
      ),
    ),
  ),
);

/// Loads the SDK's Roboto so text renders as text.
Future<void> _loadRobotoFromSdk() async {
  final root = Platform.environment['FLUTTER_ROOT'];
  if (root == null) {
    throw StateError(
      'FLUTTER_ROOT is unset; run this through `flutter test` so the SDK '
      'fonts can be found',
    );
  }
  final fonts = Directory('$root/bin/cache/artifacts/material_fonts');
  if (!fonts.existsSync()) {
    throw StateError('no material fonts at ${fonts.path}');
  }

  final loader = FontLoader('Roboto');
  for (final weight in const ['regular', 'medium', 'bold']) {
    final file = File('${fonts.path}/roboto-$weight.ttf');
    if (!file.existsSync()) continue;
    loader.addFont(Future.value(ByteData.sublistView(file.readAsBytesSync())));
  }
  await loader.load();
}
