# LUKS initrd transport threat review

Status: accepted for the first implementation. This review unblocks `LUK-02`;
it does not enable boot unlock by itself.

## Decision

The first initrd transport is **wired Ethernet, IPv4, one inbound TCP listener**.
The phone already reconnects to the verifier endpoint saved at pairing, so the
boot client does not add discovery, DNS, HTTP, TLS, D-Bus or a daemon. The
existing PhoneAuth handshake authenticates both peers and encrypts every
application frame above this untrusted byte stream.

The deployment must give the booting machine a stable address (a static address
or DHCP reservation) and a fixed PhoneAuth port. Kernel `ip=dhcp` is an
acceptable minimal address setup; the kernel documents that boot-time IP
autoconfiguration works independently of NFS. A systemd initrd may instead use
systemd-networkd with one `.network` file. Neither choice changes the PhoneAuth
wire protocol. See the [kernel IP autoconfiguration documentation](https://docs.kernel.org/admin-guide/nfs/nfsroot.html)
and [systemd-networkd](https://www.freedesktop.org/software/systemd/man/latest/systemd-networkd.service.html).

Not selected for version 1:

- **Wi-Fi:** rejected. It either places a reusable PSK and a wireless stack in
  the normally readable initrd/boot partition or requires an interactive
  provisioning design that does not exist.
- **BLE:** deferred. The desktop implementation depends on BlueZ and D-Bus,
  neither of which is available here. A raw HCI implementation would add a
  second radio stack before disk unlock and needs its own review.
- **USB gadget, QR and Internet relay:** no implemented phone peer, no need in
  the supported boot flow, and materially more code or hardware.

## Trust boundary and assumptions

- Ethernet, switches, DHCP and every remote address are hostile. They provide
  availability only, never identity or confidentiality.
- The paired phone identity and the dedicated LUKS credential are the trust
  roots. A connection is useless until the existing signed handshake matches
  the baked-in pairing record.
- The initrd is trusted code. Secure Boot (or an equivalent authenticated boot
  chain) is required before treating PhoneAuth as more than convenience; an
  attacker who can replace the initrd can capture the key after approval or
  bypass the client entirely.
- The boot console and kernel command line are not secret. They may contain
  addresses, port and credential identifiers, never a disk key, Wi-Fi secret,
  private credential or recovery passphrase.
- Physical memory, DMA and a compromised kernel remain able to capture the
  unlocked volume key. They are outside the protection this transport adds.

## Attacks and controls

| Attack | Control / accepted result |
|---|---|
| Spoofed phone or server | Mutual signed handshake is checked against the stored identities before an unlock request. |
| Sniffing or modifying LAN traffic | X25519/HKDF and ChaCha20-Poly1305 protect the session; modified frames fail closed. |
| Replay from an earlier boot | Fresh handshake nonces, exporter-bound request, request ID and expiry; a response cannot move between sessions. |
| DHCP, ARP or routing spoofing | May redirect or deny the connection, but cannot produce the paired signature. Timeout falls back to the offline keyslot. |
| Connection/frame flood | One listener, one candidate at a time, bounded frame lengths and a single overall timeout. No retry loop in the initrd. |
| Slow client | Read/write deadlines consume the same overall timeout; the recovery prompt is not postponed indefinitely. |
| Unexpected interface exposure | IPv4 only, fixed port, no discovery response and no other listener. A firewall may narrow source networks but is not an authentication control. |
| Boot-log disclosure | Diagnostics only on stderr; the exact key bytes are written once to stdout for `cryptsetup`. No request, response, key or plaintext is logged. |
| Phone absent, flat or denies | Non-zero exit and empty stdout; boot immediately proceeds to the mandatory offline passphrase keyslot. |
| Reused authorization signature as a disk key | Impossible by design: LUKS uses a separate hardware-backed wrapping credential and returns an unwrapped random key; signatures are never KDF input. |

## Implementation gates

`LUK-02` must keep the initrd crate dependency-free beyond the existing protocol
and verifier crates, reuse the protocol's length bounds, use a fixed configured
port, and enforce one end-to-end timeout. It must not import the agent, BlueZ,
D-Bus, an HTTP stack or a TLS stack.

`LUK-03` must define a versioned wrapping envelope and a dedicated
hardware-backed credential. The disk key is random; it is never a signature,
signature hash or deterministic biometric output.

`LUK-04` may install a systemd-initrd unit only when the transport and wrapping
path work. The unit must order after wired networking, feed stdout directly to
`cryptsetup`, and preserve password fallback. systemd documents `_netdev`,
`x-initrd.attach` and bounded token/key timeouts in
[`crypttab`](https://www.freedesktop.org/software/systemd/man/latest/crypttab.html).

Before `LUK-05` can enable the feature, setup must prove that a distinct offline
keyslot opens the volume and record a recovery drill. `LUK-06` then exercises
real wired boot, denial, timeout, invalid frames, phone absence and fallback.

## Review trigger

Review this decision again before adding Wi-Fi, BLE/HCI, IPv6, discovery,
multiple concurrent clients, an Internet relay, unattended retry, or any
secret to the kernel command line or initrd. Those are new trust boundaries,
not transport configuration.
