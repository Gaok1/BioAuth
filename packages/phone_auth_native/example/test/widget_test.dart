// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';

import 'package:phone_auth_native_example/main.dart';

void main() {
  testWidgets('shows native security status shell', (tester) async {
    await tester.pumpWidget(const PluginExample());

    expect(find.text('PhoneAuth Native'), findsOneWidget);
  });
}
