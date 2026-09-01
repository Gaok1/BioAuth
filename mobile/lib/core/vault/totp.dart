/// Time-based one-time passwords, RFC 6238.
///
/// The second factor lives on the phone next to the first, which is a real
/// weakening and worth naming: a password manager that also holds the TOTP
/// seed turns two factors into one device. It is here because the alternative
/// people actually choose is a screenshot of the QR code in their photo roll,
/// and this is behind the same Keystore key and the same biometric as the
/// password it belongs to.
///
/// The seed never leaves the vault. A code is derived on demand and is not
/// stored, because a stored code is a code that outlives its window.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// The window every authenticator agrees on.
const Duration totpPeriod = Duration(seconds: 30);

/// Digits in a generated code. Six is what every issuer prints.
const int totpDigits = 6;

class TotpException implements Exception {
  const TotpException(this.message);
  final String message;

  @override
  String toString() => message;
}

/// RFC 4648 base32, which is how every issuer writes a TOTP seed.
const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// A parsed seed, ready to generate from.
class TotpSecret {
  const TotpSecret(
    this.bytes, {
    this.digits = totpDigits,
    this.period = totpPeriod,
  });

  final Uint8List bytes;
  final int digits;
  final Duration period;

  /// Reads a seed the way a person copies one: with spaces, in lower case,
  /// sometimes padded, sometimes not.
  ///
  /// Padding is accepted and discarded rather than required. Issuers disagree
  /// about it, and a seed that works in one authenticator and not in this one
  /// would look like this app being broken.
  factory TotpSecret.parse(
    String secret, {
    int digits = totpDigits,
    Duration period = totpPeriod,
  }) {
    if (digits < 6 || digits > 8) {
      throw const TotpException('Um código TOTP tem de 6 a 8 dígitos');
    }
    if (period.inSeconds < 1 || period.inSeconds > 300) {
      throw const TotpException('Janela TOTP fora do intervalo aceitável');
    }

    final cleaned = secret
        .replaceAll(RegExp(r'[\s-]'), '')
        .replaceAll('=', '')
        .toUpperCase();
    if (cleaned.isEmpty) throw const TotpException('A chave TOTP está vazia');

    final out = <int>[];
    var accumulator = 0;
    var bits = 0;
    for (final character in cleaned.split('')) {
      final index = _alphabet.indexOf(character);
      if (index < 0) {
        throw const TotpException('A chave TOTP tem um caractere inválido');
      }
      accumulator = (accumulator << 5) | index;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((accumulator >> bits) & 0xff);
      }
    }
    if (out.isEmpty) throw const TotpException('A chave TOTP é curta demais');
    return TotpSecret(Uint8List.fromList(out), digits: digits, period: period);
  }

  /// Reads an `otpauth://totp/...` URI, which is what a QR code holds.
  ///
  /// The label and issuer are ignored: this vault already has a name and a
  /// site for the item, and a second opinion about what to call it would just
  /// disagree with the first.
  factory TotpSecret.fromUri(String uri) {
    final parsed = Uri.tryParse(uri);
    if (parsed == null || parsed.scheme != 'otpauth' || parsed.host != 'totp') {
      throw const TotpException('Isto não é um otpauth://totp');
    }
    final secret = parsed.queryParameters['secret'];
    if (secret == null || secret.isEmpty) {
      throw const TotpException('O otpauth não traz uma chave');
    }
    // SHA-1 is the only algorithm every issuer and every authenticator agree
    // on, and it is what the RFC specifies. An `algorithm=` naming anything
    // else is refused rather than silently generating wrong codes.
    final algorithm = parsed.queryParameters['algorithm']?.toUpperCase();
    if (algorithm != null && algorithm != 'SHA1') {
      throw TotpException('Algoritmo TOTP não suportado: $algorithm');
    }
    return TotpSecret.parse(
      secret,
      digits:
          int.tryParse(parsed.queryParameters['digits'] ?? '') ?? totpDigits,
      period: Duration(
        seconds:
            int.tryParse(parsed.queryParameters['period'] ?? '') ??
            totpPeriod.inSeconds,
      ),
    );
  }
}

/// One code, and how long it has left.
class TotpCode {
  const TotpCode({required this.digits, required this.expiresAt});

  final String digits;
  final DateTime expiresAt;

  /// Whole seconds remaining, floored at zero.
  int secondsRemaining(DateTime now) {
    final remaining = expiresAt.difference(now).inSeconds;
    return remaining < 0 ? 0 : remaining;
  }
}

/// Generates the code for `at`.
///
/// The counter is seconds-since-epoch divided by the period, which means the
/// phone's clock is what decides. A device minutes out of step generates codes
/// nothing accepts, and there is no fix for that here — it belongs to the
/// clock, not to this function.
Future<TotpCode> generateTotp(TotpSecret secret, {DateTime? at}) async {
  final now = (at ?? DateTime.now()).toUtc();
  final seconds = now.millisecondsSinceEpoch ~/ 1000;
  final period = secret.period.inSeconds;
  final counter = seconds ~/ period;

  final message = Uint8List(8);
  var remaining = counter;
  for (var index = 7; index >= 0; index--) {
    message[index] = remaining & 0xff;
    remaining >>= 8;
  }

  final mac = await Hmac.sha1().calculateMac(
    message,
    secretKey: SecretKey(secret.bytes),
  );
  final hash = mac.bytes;

  // The dynamic truncation of RFC 4226: the low nibble of the last byte picks
  // where the four bytes come from, so no fixed slice of the HMAC is what an
  // attacker sees repeatedly.
  final offset = hash[hash.length - 1] & 0x0f;
  final binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

  final modulus = _pow10(secret.digits);
  final code = (binary % modulus).toString().padLeft(secret.digits, '0');

  return TotpCode(
    digits: code,
    expiresAt: DateTime.fromMillisecondsSinceEpoch(
      (counter + 1) * period * 1000,
      isUtc: true,
    ),
  );
}

int _pow10(int exponent) {
  var value = 1;
  for (var index = 0; index < exponent; index++) {
    value *= 10;
  }
  return value;
}

/// Whether a string could be a TOTP seed, for a form that wants to say so
/// before the user leaves the field.
bool looksLikeTotpSecret(String value) {
  try {
    TotpSecret.parse(value);
    return true;
  } on TotpException {
    return false;
  }
}

/// A seed written back as base32, which is the form a vault item stores.
///
/// The inverse of [TotpSecret.parse]. Storing the canonical form rather than
/// what the user pasted means an item added from a QR link and one typed by
/// hand are the same bytes, and a restore does not see them as two items.
String totpSecretToBase32(TotpSecret secret) {
  final base32 = StringBuffer();
  var accumulator = 0;
  var bits = 0;
  for (final byte in secret.bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      base32.write(_alphabet[(accumulator >> bits) & 31]);
    }
  }
  if (bits > 0) base32.write(_alphabet[(accumulator << (5 - bits)) & 31]);
  return base32.toString();
}

/// The `otpauth` URI for a seed, for the rare case of moving one out.
///
/// Deliberately not offered anywhere in the UI yet. It exists so that the
/// parser has an inverse to be tested against, which is how a round-trip bug
/// gets caught before somebody's second factor stops working.
/// Reads whichever of the two stored forms an item holds.
///
/// See [storedTotpSecret] for why there are two.
TotpSecret readTotpSecret(String stored) {
  final trimmed = stored.trim();
  return trimmed.toLowerCase().startsWith('otpauth://')
      ? TotpSecret.fromUri(trimmed)
      : TotpSecret.parse(trimmed);
}

/// The form an item stores a seed in.
///
/// Bare base32 while the seed uses the six digits and thirty-second window
/// everything defaults to, which is nearly always, and which keeps an item
/// added from a QR link byte-identical to one typed by hand — the property a
/// restore relies on to not see them as two accounts.
///
/// A seed that differs is stored as a canonical `otpauth://` URI instead,
/// because at that point the digits and the window *are* part of the secret.
/// Dropping them and reading the seed back at six-and-thirty does not fail: it
/// produces a plausible six-digit code that no issuer will ever accept, every
/// time, with nothing on screen to suggest the app is the reason. An
/// authenticator that is confidently wrong is worse than one that refuses.
String storedTotpSecret(TotpSecret secret) =>
    secret.digits == totpDigits && secret.period == totpPeriod
    ? totpSecretToBase32(secret)
    : encodeTotpSecret(secret);

String encodeTotpSecret(TotpSecret secret, {String label = ''}) {
  return Uri(
    scheme: 'otpauth',
    host: 'totp',
    path: label.isEmpty ? '/' : '/${Uri.encodeComponent(label)}',
    queryParameters: {
      'secret': totpSecretToBase32(secret),
      'digits': '${secret.digits}',
      'period': '${secret.period.inSeconds}',
    },
  ).toString();
}
