# LUKS initrd transport threat review

Status: accepted and implemented for `LUK-02`; amended below for `LUK-04`,
which moves the link from wired Ethernet to the USB cable and turns boot
unlock on as an opt-in.

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

## Amendment: the cable, not the LAN (`LUK-04`)

Status: accepted for the first boot unlock. It replaces the address setup
above, not the handshake, the framing or the client.

The machine that needs unlocking usually has no network at boot: no DHCP
reservation has been made for it, the wireless it normally uses is unreachable
by design, and a laptop away from its desk has nothing at all. So the first
shipped transport is **the phone on the USB cable, with USB tethering on**.

The phone becomes the DHCP server and the gateway; the booting machine is the
only client on that subnet. Nothing else is on the link, no router or access
point is involved, and no infrastructure has to exist for the unlock to work.
Above it, nothing changes: the same IPv4, the same single inbound TCP listener,
the same signed handshake, the same `luks.unlock` exchange. The kernel needs
`usbnet` and the RNDIS/CDC drivers, and the initrd runs DHCP on whatever
interface they bind.

What this adds over wired Ethernet:

- **Discovery, in one direction only.** The address the phone hands out is not
  the address saved at pairing, and recent Android randomises the tether
  prefix, so the phone probes the /24 it is the gateway of for the port it
  already knows. It probes nothing else: interfaces are matched by name against
  the USB tether ones, so the user's home network is never swept. The booting
  machine still discovers nothing and still answers exactly one connection.
- **A hostile peer that is now certainly present.** The cable is a link to one
  device instead of a segment shared with many, which is a smaller surface than
  the accepted one, not a larger one. Everything above still treats the bytes
  as hostile.

Not changed by this amendment: no Wi-Fi, no BLE, no IPv6, no DNS, no default
route from the phone, no relay, no unattended retry. The `.network` file
refuses each of those explicitly rather than by omission.

### The handshake key on unencrypted boot media

The gate above says the long-lived handshake private key must not be copied
into the initrd image. **This implementation does copy a key there**, through
`boot.initrd.secrets`, which appends it at `nixos-rebuild` time and keeps it out
of the world-readable Nix store — but puts it on a boot partition that anyone
holding the disk can read. That is a knowing deviation, and it is why boot
unlock is opt-in and off by default.

What limits it:

- The key is a **boot-only identity**, separate from the agent's. Reading it
  buys the ability to impersonate this machine's *boot* to a paired phone. It
  is not the agent's identity, so it does not authenticate a `sudo`, a vault
  open or an SSH signature, and the phone can revoke it on its own.
- Using it still requires the phone, on the cable, and a fingerprint on a
  prompt that names the machine and the volume. It is an attack that has to be
  approved by the person being attacked.
- The volume key is never derived from it. It stays a random 32-byte credential
  wrapped by a hardware key on the phone.

Closing the deviation means a fresh boot identity that is authenticated at boot
rather than stored — a QR on the console, or a TPM-sealed key released only to
a measured initrd. Both are follow-up work, and neither is required to keep the
passphrase fallback honest.

## Trust boundary and assumptions

- Ethernet, switches, DHCP and every remote address are hostile. They provide
  availability only, never identity or confidentiality.
- The paired phone identity and the dedicated LUKS credential are the trust
  roots. A connection is useless until the existing signed handshake matches
  the baked-in pairing record.
- The initrd is trusted code but **not confidential**: the boot partition can
  normally be read without unlocking root. Secure Boot (or an equivalent
  authenticated boot chain) is required for integrity, but does not hide it.
  The long-lived handshake private key therefore must not be copied into the
  initrd image. `LUK-04` must provide it at runtime from a confidential,
  authenticated source or replace it with a fresh QR-authenticated boot
  identity before enabling the unit.
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

`LUK-02` keeps the initrd crate dependency-free beyond the existing protocol,
session and verifier crates, shares the session crate's bounded framing, uses a
fixed configured port, and enforces one end-to-end timeout. It does not import
the agent, BlueZ, D-Bus, an HTTP stack or a TLS stack.

`LUK-03` defines the versioned envelope and dedicated hardware-backed wrapping
credential in [`luks-wrapping.md`](luks-wrapping.md). The disk key is random;
it is never a signature, signature hash or deterministic biometric output.

`LUK-04` may install a systemd-initrd unit only when the transport and wrapping
path work **and the handshake private key is not embedded in the public initrd**.
The unit must order after wired networking, feed stdout directly to
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
