/// QR bootstrap onto a local-network link.
///
/// The desktop listens; the phone dials. There is nothing to discover — the
/// address comes from the scanned code, or from the pairing record — so
/// [discoverPeers] is empty and a peer's `transportId` is its `host:port`.
///
/// # Trust
///
/// Confidentiality and peer authentication come from the PhoneAuth handshake,
/// never from the network. The address dialled is a routing detail and is not
/// identity: a session is usable only once the desktop has proved possession of
/// the key the scanned code committed to, or of the key stored at pairing.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'auth_transport.dart';
import 'length_prefixed_framer.dart';
import 'secure_session_establisher.dart';

/// Both sides must report this exact string: it is hashed into the session
/// binding, so a mismatch makes every request fail with no other symptom.
const String qrNetworkTransportName = 'QrNetworkTransport';

const Duration _connectTimeout = Duration(seconds: 10);

const TransportSecurityProperties _rawProperties = TransportSecurityProperties(
  transportName: qrNetworkTransportName,
  confidential: false,
  peerAuthenticated: false,
  requiresNetwork: true,
  // Being on the same network is not proximity, and even if it were, proximity
  // is never authorization.
  proximitySignal: false,
  expectedLatency: Duration(milliseconds: 80),
);

/// Opens a socket to an endpoint. Substituted in tests for a local pair.
typedef SocketConnector =
    Future<Socket> Function(String host, int port, Duration timeout);

class QrNetworkTransport implements AuthTransport {
  QrNetworkTransport({
    required SecureSessionEstablisher sessionEstablisher,
    SocketConnector? connector,
  }) : _sessionEstablisher = sessionEstablisher,
       _connect = connector ?? _connectSocket;

  final SecureSessionEstablisher _sessionEstablisher;
  final SocketConnector _connect;

  @override
  TransportSecurityProperties get securityProperties => _rawProperties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}

  @override
  Stream<TransportPeer> discoverPeers() => const Stream<TransportPeer>.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    final (host, port) = parseEndpoint(peer.transportId);
    final socket = await _connect(host, port, _connectTimeout);
    final link = TcpTransportLink(socket, originLabel: peer.transportId);
    try {
      return await _sessionEstablisher.establish(link, expectation);
    } on Object {
      await link.close();
      rethrow;
    }
  }
}

/// Splits a bootstrap's `ep` field into a host and a port.
///
/// IPv6 literals arrive bracketed, so splitting on the last colon rather than
/// the first is what keeps `[fe80::1]:8765` from parsing as host `[fe80`.
(String, int) parseEndpoint(String endpoint) {
  final separator = endpoint.lastIndexOf(':');
  if (separator <= 0 || separator == endpoint.length - 1) {
    throw FormatException('endpoint `$endpoint` is not `host:port`');
  }
  final port = int.tryParse(endpoint.substring(separator + 1));
  if (port == null || port < 1 || port > 65535) {
    throw FormatException('endpoint `$endpoint` has no usable port');
  }
  var host = endpoint.substring(0, separator);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  return (host, port);
}

/// A [RawTransportLink] over a TCP socket with length-prefixed frames.
class TcpTransportLink implements RawTransportLink {
  TcpTransportLink(this._socket, {required String originLabel})
    : _originLabel = '$qrNetworkTransportName • $originLabel' {
    _subscription = _socket.listen(
      (chunk) {
        try {
          for (final frame in _framer.addChunk(chunk)) {
            if (!_incoming.isClosed) _incoming.add(frame);
          }
        } on FramingException catch (error, stack) {
          _incoming.addError(error, stack);
        }
      },
      onError: (Object error, StackTrace stack) =>
          _incoming.addError(error, stack),
      onDone: () {
        // A partial frame at EOF is a peer that went away mid-message, not a
        // clean close; surfacing it stops a truncated hello from looking like
        // an empty stream.
        if (_framer.hasPartialFrame && !_incoming.isClosed) {
          _incoming.addError(
            const FramingException('connection closed mid-frame'),
          );
        }
        if (!_incoming.isClosed) _incoming.close();
      },
    );
  }

  final Socket _socket;
  final String _originLabel;
  final LengthPrefixedFramer _framer = LengthPrefixedFramer();
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  late final StreamSubscription<Uint8List> _subscription;
  bool _closed = false;

  @override
  String get originLabel => _originLabel;

  @override
  TransportSecurityProperties get rawSecurityProperties => _rawProperties;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> send(Uint8List frame) async {
    if (_closed) throw const FramingException('link is closed');
    _socket.add(encodeFrame(frame));
    await _socket.flush();
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription.cancel();
    _socket.destroy();
    if (!_incoming.isClosed) await _incoming.close();
  }
}

Future<Socket> _connectSocket(String host, int port, Duration timeout) =>
    Socket.connect(host, port, timeout: timeout);
