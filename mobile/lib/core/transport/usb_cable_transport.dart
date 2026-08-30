/// Reaches the computer over the USB cable instead of over the network.
///
/// With USB tethering on, the cable is a two-host link: the phone is the
/// gateway and the computer is its only client. No router, no access point, no
/// Wi-Fi password, and nothing else on the subnet. That is what makes it the
/// transport for boot unlock — a machine sitting at its passphrase prompt has
/// no address, no name and usually no network at all, and the phone in the
/// user's hand can hand it all three.
///
/// It is still IP, so the transport underneath is unchanged and so is the
/// session binding: this class dials a different address, it does not speak a
/// different protocol. `transportName` stays whatever the wrapped transport
/// reports, because both sides hash it and a new name would fail every request
/// with no other symptom.
///
/// # Why it has to search
///
/// The computer's address on the cable comes from the phone's own DHCP server.
/// It is not the address stored at pairing, and nothing tells the phone what it
/// became — Android picks the tether prefix and recent versions randomise it.
/// So the phone probes the link it is the gateway of, for the port it already
/// knows from the pairing record, and dials whoever accepts.
///
/// # Only the cable is searched
///
/// Interfaces are matched by name against the USB tether ones, and only links
/// small enough to be a cable are swept. Sweeping the Wi-Fi subnet instead
/// would be a port scan of the user's home network: rude, slow, and a good way
/// to look like malware. With no cable attached there is nothing to scan and
/// the call costs one interface listing.
library;

import 'dart:async';
import 'dart:io';

import 'auth_transport.dart';
import 'qr_network_transport.dart' show parseEndpoint;
import 'secure_session_establisher.dart';

/// Lists the USB links this phone holds. Substituted in tests.
typedef CableLinkLister = Future<List<CableLink>> Function();

/// Answers whether something accepts TCP at `host:port`. Substituted in tests.
typedef PortProbe =
    Future<bool> Function(String host, int port, Duration timeout);

/// One IPv4 address this phone holds on a USB link, with its subnet.
class CableLink {
  const CableLink({required this.address, required this.prefixLength});

  /// The phone's own address, dotted-quad.
  final String address;

  /// Bits of network in that address, as the kernel reports them. A cable is
  /// a small subnet; anything wide is something else wearing a cable's name.
  final int prefixLength;
}

/// Android's USB tether interfaces: `rndis0` on most devices, `ncm0` on newer
/// ones, `usb0` on a few. Wi-Fi (`wlan0`) and the hotspot (`ap0`) are
/// deliberately absent — this transport exists to avoid them.
bool isUsbLinkName(String name) =>
    RegExp(r'^(rndis|ncm|usb|eem)\d*$').hasMatch(name);

/// The widest link still worth sweeping: 254 addresses, one of which answers.
///
/// A tether hands out a /24 today, and a narrower one only makes the search
/// shorter. Anything wider is not a cable, and probing it would be a scan of
/// someone's network.
const int _narrowestSweptPrefix = 24;

class UsbCableTransport implements AuthTransport {
  UsbCableTransport({
    required AuthTransport link,
    CableLinkLister? links,
    PortProbe? probe,
    this.probeTimeout = const Duration(milliseconds: 400),
    this.maxCandidates = 4,
    this.probeConcurrency = 32,
  }) : _link = link,
       _links = links ?? _usbLinks,
       _probe = probe ?? _probePort;

  final AuthTransport _link;
  final CableLinkLister _links;
  final PortProbe _probe;

  /// How long one address has to accept a connection. Over a cable an answer
  /// is immediate; this bounds the silent ones, and there can be 253 of them.
  final Duration probeTimeout;

  /// How many answering addresses are worth a handshake. More than one only
  /// happens when something else on the cable listens on the same port.
  final int maxCandidates;

  /// How many addresses are probed at once.
  final int probeConcurrency;

  @override
  TransportSecurityProperties get securityProperties =>
      _link.securityProperties;

  @override
  Future<void> start() => _link.start();

  @override
  Future<void> stop() => _link.stop();

  @override
  Stream<TransportPeer> discoverPeers() => _link.discoverPeers();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    // Pairing is first contact, and the scanned code commits to one endpoint.
    // Substituting an address there would be this class deciding who the user
    // is pairing with.
    if (expectation is PairedVerifier) {
      for (final candidate in await cableEndpoints(peer.transportId)) {
        try {
          return await _link.connect(
            TransportPeer(
              transportId: candidate,
              displayName: peer.displayName,
            ),
            expectation,
          );
        } on Object {
          // Accepting TCP is not being the computer. Keep going, and keep the
          // saved address as the answer.
        }
      }
    }
    return _link.connect(peer, expectation);
  }

  /// Endpoints on the cable that accept the same port as [savedEndpoint].
  ///
  /// Empty when no cable is attached, when tethering is off, and when the
  /// saved endpoint has no port to reuse.
  Future<List<String>> cableEndpoints(String savedEndpoint) async {
    final int port;
    try {
      (_, port) = parseEndpoint(savedEndpoint);
    } on FormatException {
      return const [];
    }

    final List<CableLink> links;
    try {
      links = await _links();
    } on Object {
      // No interface list is the same answer as no cable: use the saved
      // address. It is never a reason to fail an authorization.
      return const [];
    }

    final hosts = [for (final link in links) ...subnetHosts(link)];
    if (hosts.isEmpty) return const [];

    final found = <String>[];
    for (var index = 0; index < hosts.length; index += probeConcurrency) {
      final batch = hosts.skip(index).take(probeConcurrency).toList();
      final answers = await Future.wait([
        for (final host in batch) _probe(host, port, probeTimeout),
      ]);
      for (var slot = 0; slot < batch.length; slot++) {
        if (!answers[slot]) continue;
        found.add('${batch[slot]}:$port');
        if (found.length >= maxCandidates) return found;
      }
    }
    return found;
  }
}

/// Every usable address on [link]'s subnet except the phone's own, nearest
/// first.
///
/// Nearest-first is what makes the search finish immediately in practice: a
/// tether gateway hands out the address next to its own, so the computer is
/// `.130` when the phone is `.129`, and `.2` when the phone is `.1`.
List<String> subnetHosts(CableLink link) {
  final own = _parseIpv4(link.address);
  if (own == null) return const [];
  if (link.prefixLength < _narrowestSweptPrefix || link.prefixLength > 32) {
    return const [];
  }

  final mask = (0xFFFFFFFF << (32 - link.prefixLength)) & 0xFFFFFFFF;
  final network = own & mask;
  final broadcast = network | (~mask & 0xFFFFFFFF);

  final hosts = <String>[];
  for (var distance = 1; distance <= broadcast - network; distance++) {
    for (final address in [own + distance, own - distance]) {
      // The network and broadcast addresses are not hosts, and neither is the
      // phone itself.
      if (address <= network || address >= broadcast) continue;
      hosts.add(_formatIpv4(address));
    }
  }
  return hosts;
}

int? _parseIpv4(String address) {
  final octets = address.split('.');
  if (octets.length != 4) return null;
  var packed = 0;
  for (final octet in octets) {
    final value = int.tryParse(octet);
    if (value == null || value < 0 || value > 255) return null;
    packed = (packed << 8) | value;
  }
  return packed;
}

String _formatIpv4(int address) => [
  (address >> 24) & 0xFF,
  (address >> 16) & 0xFF,
  (address >> 8) & 0xFF,
  address & 0xFF,
].join('.');

Future<List<CableLink>> _usbLinks() async {
  final interfaces = await NetworkInterface.list(
    includeLoopback: false,
    type: InternetAddressType.IPv4,
  );
  return [
    for (final interface in interfaces)
      if (isUsbLinkName(interface.name))
        for (final address in interface.addresses)
          CableLink(
            address: address.address,
            prefixLength: address.prefixLength,
          ),
  ];
}

Future<bool> _probePort(String host, int port, Duration timeout) async {
  try {
    final socket = await Socket.connect(host, port, timeout: timeout);
    socket.destroy();
    return true;
  } on Object {
    return false;
  }
}
