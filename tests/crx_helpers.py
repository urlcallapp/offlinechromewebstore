"""Structurally valid synthetic headers, NOT cryptographically signed fixtures."""
import hashlib
import struct

KEY = b'synthetic developer key, not a DER key'


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    return varint((number << 3) | 2) + varint(len(value)) + value


def crx3_header(key=KEY, raw_id=None, extra=b'', proof=None):
    raw_id = hashlib.sha256(key).digest()[:16] if raw_id is None else raw_id
    proof = field(1, key) + field(2, b'not a real signature') if proof is None else proof
    return field(2, proof) + field(10000, field(1, raw_id)) + extra


def crx3(archive, **kwargs):
    header = crx3_header(**kwargs)
    return b'Cr24' + struct.pack('<II', 3, len(header)) + header + archive


def key_id(key=KEY):
    return ''.join(chr(97 + int(nibble, 16)) for nibble in hashlib.sha256(key).hexdigest()[:32])
