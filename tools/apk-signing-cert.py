#!/usr/bin/env python3
"""Print, and optionally check, the certificate an APK was signed with.

Why this is not a question the filename answers. A release APK signed with
Android's debug key — which is what the release workflow falls back to when the
four signing secrets are absent — is named exactly like one signed with the
project key. Only the channel shows up in the filename, and the channel is not
the key.

Why the key matters more than it sounds. Android refuses to install an APK over
one signed with a different key. The only way forward is an uninstall, and an
uninstall destroys every Keystore-bound pairing, passkey and vault item on the
device: the pairing cannot be re-derived, and the vault cannot be recovered
from the desktop. So "which key signed this" decides whether a release is an
update or a reset, and it is worth asking before an install rather than after.

    tools/apk-signing-cert.py <apk>                 # print what signed it
    tools/apk-signing-cert.py <apk> --expect <hex>  # and fail if it differs
    tools/apk-signing-cert.py <apk> --expect project

`project` is the key every release so far was signed with, recorded below. A
fresh keystore legitimately changes it, and changing it here is the moment to
notice that every installed copy has to be uninstalled first.

Reads the APK Signing Block directly: v1 signatures live in `META-INF` where a
zip tool can reach them, but modern Flutter builds ship v2/v3 only, and those
live in a block between the entries and the central directory. No Android SDK
needed, which is the point — the machine doing a release smoke test is not
necessarily the machine that built it.
"""

import argparse
import hashlib
import struct
import sys

MAGIC = b'APK Sig Block 42'

# `apksigner verify --print-certs` prints this as "Signer #1 certificate
# SHA-256 digest". Subject: CN=BioAuth, OU=Personal, O=BioAuth, C=BR.
PROJECT_CERT = 'e331145ec3591f16f3690e606587874f5e81edbee1f14a209988787ee6ba1bb8'

# Scheme blocks that carry signer certificates. v4 lives in a separate file and
# carries none, so it is not listed.
SCHEMES = {0x7109871A: 'v2', 0xF05368C0: 'v3', 0x1B93AD61: 'v3.1'}


def signing_block(data):
    """The pairs region of the APK Signing Block, or None if there is none."""
    end = data.rfind(MAGIC)
    if end < 0:
        return None
    # The block's size is written twice, before the pairs and after them, and
    # excludes only the leading copy. Read the trailing one: it is the one at a
    # known offset from the magic.
    size = struct.unpack_from('<Q', data, end - 8)[0]
    start = end + len(MAGIC) - size - 8
    if start < 0:
        return None
    return data[start + 8:end - 8]


def pairs(block):
    """`(id, value)` for each length-prefixed pair in the block."""
    offset = 0
    while offset + 12 <= len(block):
        length = struct.unpack_from('<Q', block, offset)[0]
        if length < 4 or offset + 8 + length > len(block):
            return
        identifier = struct.unpack_from('<I', block, offset + 8)[0]
        yield identifier, block[offset + 12:offset + 8 + length]
        offset += 8 + length


def elements(buffer):
    """Each element of a sequence of uint32-length-prefixed elements."""
    offset = 0
    while offset + 4 <= len(buffer):
        length = struct.unpack_from('<I', buffer, offset)[0]
        if offset + 4 + length > len(buffer):
            return
        yield buffer[offset + 4:offset + 4 + length]
        offset += 4 + length


def certificates(value):
    """The signer certificates in one scheme block's value.

    Three levels down, and the first one is easy to miss: the value is itself a
    length-prefixed sequence of signers, so iterating it as a sequence yields
    that whole sequence as a single element and every offset after it is one
    level out. The symptom is a plausible-looking digest of the wrong bytes.
    """
    found = []
    signers = next(elements(value), b'')
    for signer in elements(signers):
        parts = list(elements(signer))
        if not parts:
            continue
        # signed data comes first in v2 and v3 alike, and within it the
        # certificates come after the digests.
        blocks = list(elements(parts[0]))
        if len(blocks) >= 2:
            found.extend(elements(blocks[1]))
    return found


def common_name(certificate):
    """The subject CN, read out of the DER without an X.509 library."""
    marker = b'\x55\x04\x03'  # id-at-commonName
    index = certificate.find(marker)
    while index >= 0:
        tag = certificate[index + 3]
        if tag in (0x0C, 0x13, 0x16):  # UTF8String, PrintableString, IA5String
            length = certificate[index + 4]
            return certificate[index + 5:index + 5 + length].decode('utf-8', 'replace')
        index = certificate.find(marker, index + 1)
    return '(subject not parsed)'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk')
    parser.add_argument(
        '--expect',
        help='a SHA-256 certificate digest, or "project" for the recorded one',
    )
    arguments = parser.parse_args()

    with open(arguments.apk, 'rb') as handle:
        data = handle.read()

    block = signing_block(data)
    if block is None:
        print('no APK signing block: v1-signed only, or not signed at all')
        return 1

    digests = {}
    for identifier, value in pairs(block):
        scheme = SCHEMES.get(identifier)
        if scheme is None:
            continue
        for certificate in certificates(value):
            digest = hashlib.sha256(certificate).hexdigest()
            digests.setdefault(digest, (scheme, common_name(certificate)))

    if not digests:
        print('a signing block with no certificate in it')
        return 1

    for digest, (scheme, name) in digests.items():
        print(f'{scheme}  {name}')
        print(f'    SHA-256 digest  {digest}')

    if not arguments.expect:
        return 0

    expected = PROJECT_CERT if arguments.expect == 'project' else arguments.expect
    expected = expected.lower().replace(':', '')
    if len(digests) != 1:
        print(f'\n{len(digests)} different certificates, so no single answer')
        return 1
    if expected not in digests:
        print('\nnot the expected key. Android will refuse to install this over')
        print('an existing copy, and uninstalling destroys the pairings,')
        print('passkeys and vault on the device.')
        print(f'    expected  {expected}')
        return 1
    print('\nthe expected key: this installs over an existing copy')
    return 0


if __name__ == '__main__':
    sys.exit(main())
