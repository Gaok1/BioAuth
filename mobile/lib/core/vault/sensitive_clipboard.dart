/// The clipboard, told that what it is being handed is a secret.
///
/// Since Android 13 every copy raises a preview that renders the content, so a
/// password manager copying a password put it on screen in plain text for
/// anyone standing there. The same flag is what keeps the value out of
/// clipboard history and out of a keyboard's suggestion strip, which is the
/// half that outlives the paste.
///
/// It lives on the `ClipData`, and `Clipboard.setData` has no way to set it —
/// so this goes through the plugin instead. Everywhere but Android there is
/// nothing extra to say and nothing to say it with, so the platform clipboard
/// is used as before.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

Future<void> copySensitive(String value) =>
    defaultTargetPlatform == TargetPlatform.android && !kIsWeb
    ? const PhoneAuthClipboard().copySensitive(value)
    : Clipboard.setData(ClipboardData(text: value));
