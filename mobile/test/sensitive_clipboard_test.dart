/// Where a copied secret goes.
///
/// The vault's whole output is one string at a time on the clipboard, and on
/// Android the platform renders a preview of it unless the clip says not to.
/// Flutter's own clipboard cannot say it, so the only thing that separates a
/// password shown to the room from one that is not is which channel this call
/// lands on.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/vault/sensitive_clipboard.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const native = MethodChannel('phone_auth_native');
  const platform = SystemChannels.platform;

  final calls = <MethodCall>[];

  void record(MethodChannel channel) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return null;
        });
  }

  setUp(() {
    calls.clear();
    record(native);
    record(platform);
  });

  tearDown(() {
    debugDefaultTargetPlatformOverride = null;
    for (final channel in [native, platform]) {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    }
  });

  test(
    'on Android the copy goes through the plugin that can flag it',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;

      await copySensitive('hunter2');

      expect(calls.single.method, 'copySensitive');
      expect(calls.single.arguments, 'hunter2');
    },
  );

  test(
    'elsewhere it is an ordinary copy, since there is nothing to say',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;

      await copySensitive('hunter2');

      expect(calls.single.method, 'Clipboard.setData');
    },
  );
}
