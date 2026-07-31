"""A frozen TLS ClientHello and an independent JA3/JA4 reference implementation.

The reference functions here reimplement JA3 and JA4 (TLS client) from scratch
so the Rust implementation is validated against a second, independent one.
"""

from __future__ import annotations

import hashlib
import struct


def build_client_hello(sni: str = "example.com") -> bytes:
    """Build a TLS record containing a ClientHello with GREASE, SNI, ALPN,
    supported_versions (TLS 1.3), supported_groups, and signature_algorithms."""
    ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]  # first is GREASE
    body = b""
    body += struct.pack(">H", 0x0303)  # legacy_version TLS1.2
    body += b"\x00" * 32  # random
    body += b"\x00"  # session id len
    body += struct.pack(">H", len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack(">H", c)
    body += b"\x01\x00"  # compression: null

    exts = b""

    # SNI (0x0000)
    host = sni.encode()
    sni_list = struct.pack(">H", len(host) + 3) + b"\x00" + struct.pack(">H", len(host)) + host
    exts += struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    # supported_groups (0x000a): x25519(29), secp256r1(23)
    groups = [0x001D, 0x0017]
    g = struct.pack(">H", len(groups) * 2) + b"".join(struct.pack(">H", x) for x in groups)
    exts += struct.pack(">HH", 0x000A, len(g)) + g

    # ec_point_formats (0x000b): uncompressed(0)
    epf = b"\x01\x00"
    exts += struct.pack(">HH", 0x000B, len(epf)) + epf

    # signature_algorithms (0x000d)
    sigs = [0x0403, 0x0804, 0x0401]
    s = struct.pack(">H", len(sigs) * 2) + b"".join(struct.pack(">H", x) for x in sigs)
    exts += struct.pack(">HH", 0x000D, len(s)) + s

    # ALPN (0x0010): h2, http/1.1
    protos = [b"h2", b"http/1.1"]
    alpn_list = b"".join(bytes([len(p)]) + p for p in protos)
    alpn = struct.pack(">H", len(alpn_list)) + alpn_list
    exts += struct.pack(">HH", 0x0010, len(alpn)) + alpn

    # supported_versions (0x002b): TLS1.3, TLS1.2
    vers = [0x0304, 0x0303]
    v = bytes([len(vers) * 2]) + b"".join(struct.pack(">H", x) for x in vers)
    exts += struct.pack(">HH", 0x002B, len(v)) + v

    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body  # handshake header (type + 3-byte len)
    record = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    return record, ciphers, exts_types(exts), groups, [0], sigs, vers, sni, protos


def exts_types(exts: bytes) -> list[int]:
    out = []
    p = 0
    while p + 4 <= len(exts):
        etype, elen = struct.unpack(">HH", exts[p:p + 4])
        out.append(etype)
        p += 4 + elen
    return out


def _is_grease(v: int) -> bool:
    b = v & 0xFF
    return (v >> 8) == b and (b & 0x0F) == 0x0A


def ja3(legacy_version, ciphers, ext_types, groups, point_formats) -> str:
    c = "-".join(str(x) for x in ciphers if not _is_grease(x))
    e = "-".join(str(x) for x in ext_types if not _is_grease(x))
    g = "-".join(str(x) for x in groups if not _is_grease(x))
    p = "-".join(str(x) for x in point_formats)
    raw = f"{legacy_version},{c},{e},{g},{p}"
    return hashlib.md5(raw.encode()).hexdigest(), raw


def ja4(ciphers, ext_types, sigs, versions, sni_present, alpn) -> str:
    best = max((v for v in versions if not _is_grease(v)), default=0x0303)
    ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(best, "00")
    d = "d" if sni_present else "i"
    nc = min(len([c for c in ciphers if not _is_grease(c)]), 99)
    ne = min(len([e for e in ext_types if not _is_grease(e)]), 99)
    first_alpn = alpn[0].decode()
    a = f"{first_alpn[0]}{first_alpn[-1]}"
    part_a = f"t{ver}{d}{nc:02d}{ne:02d}{a}"

    cipher_hex = sorted(f"{c:04x}" for c in ciphers if not _is_grease(c))
    part_b = hashlib.sha256(",".join(cipher_hex).encode()).hexdigest()[:12]

    ext_hex = sorted(
        f"{e:04x}" for e in ext_types if not _is_grease(e) and e not in (0x0000, 0x0010)
    )
    sig_hex = [f"{s:04x}" for s in sigs]
    raw_c = ",".join(ext_hex) + "_" + ",".join(sig_hex)
    part_c = hashlib.sha256(raw_c.encode()).hexdigest()[:12]

    return f"{part_a}_{part_b}_{part_c}"
