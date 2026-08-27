// Stitches the approval frames into the animation the README shows.
//
//     flutter test test/media/capture_screens.dart   # writes the frames
//     dart run tool/build_flow_gif.dart              # writes the animation
//
// The frames are real captures of the running app, so this only resizes and
// times them. Kept as a separate step because the capture runs under the test
// harness and this does not: `flutter test` has no way to hand a file back.

import 'dart:io';

import 'package:image/image.dart';

/// Where the capture wrote its frames, relative to the package root.
const String frameDirectory = '../docs/media/flow';

const String output = '../docs/media/approval-flow.gif';

/// Narrow enough to sit inside a README column without being scaled by the
/// browser, which is what makes a screenshot look soft.
const int width = 320;

/// One entry per frame: how long it stays on screen, in milliseconds.
///
/// The two middle frames are the biometric prompt and the signature. They are
/// genuinely brief in the app, but a reader needs longer than the app takes.
const List<({String name, int holdMs})> frames = [
  (name: '1-request', holdMs: 1600),
  (name: '2-detail', holdMs: 2200),
  (name: '3-biometric', holdMs: 1200),
  (name: '4-signing', holdMs: 1200),
  (name: '5-history', holdMs: 2400),
];

void main() {
  final animation = Image.empty();

  for (final frame in frames) {
    final file = File('$frameDirectory/${frame.name}.png');
    if (!file.existsSync()) {
      stderr.writeln(
        'missing ${file.path}\n'
        'run: flutter test test/media/capture_screens.dart',
      );
      exitCode = 1;
      return;
    }

    final decoded = decodePng(file.readAsBytesSync());
    if (decoded == null) {
      stderr.writeln('could not decode ${file.path}');
      exitCode = 1;
      return;
    }

    final resized = copyResize(
      decoded,
      width: width,
      interpolation: Interpolation.average,
    )..frameDuration = frame.holdMs;
    animation.addFrame(resized);
  }

  // The first frame of an `Image.empty()` is a placeholder with no pixels;
  // dropping it is what stops the animation opening on a blank flash.
  final assembled = Image.from(animation.frames[1]);
  for (final frame in animation.frames.skip(2)) {
    assembled.addFrame(frame);
  }

  // No dithering. GIF's 256 colours are plenty for a flat Material palette,
  // and error diffusion turns the large areas of near-solid background into
  // visible noise — which reads as a low-quality capture rather than as a
  // limitation of the format.
  File(output).writeAsBytesSync(
    encodeGif(assembled, repeat: 0, dither: DitherKernel.none),
  );
  final size = File(output).lengthSync();
  stdout.writeln('wrote $output (${(size / 1024).round()} KB)');
}
