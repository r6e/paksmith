#!/usr/bin/env python3
"""Generate a minimal .locres v2 (Optimized_CRC32) fixture for documentation.

Wire format per `docs/formats/data/locres.md`. Today's `main` emits the
124-byte single-namespace pilot fixture documented in the worked example.

The shape of the generator (NAMESPACES list of `(name, keys)` tuples
iterated to build `ns_bytes`) supports extending to multi-namespace
fixtures by adding entries — every count and offset derives from
`NAMESPACES`.

Hashes are CRC32 of the UTF-16-LE-encoded string (matching CUE4Parse's
`FTextKey.cs` for v2). Source-string hashes are CRC32 of the UTF-16-LE
source string.

Run:
    python3 tools/gen-locres-fixture.py > tests/fixtures/data/sample_v2.locres
"""

import struct
import sys
import zlib

MAGIC = bytes.fromhex("0E14747567 4A03FC 4A 15 90 9D C3 37 7F 1B".replace(" ", ""))
assert len(MAGIC) == 16, f"magic must be 16 bytes, got {len(MAGIC)}"

VERSION = 0x02  # Optimized_CRC32

# Each entry is `(namespace_name, [(key, value), ...])`.
NAMESPACES = [
    ("Game", [("key1", "Hello"), ("key2", "World")]),
]


def fstring_ascii(s: str) -> bytes:
    """Serialize ASCII string as UE FString: i32 length (incl. null) + bytes + null."""
    payload = s.encode("ascii") + b"\x00"
    return struct.pack("<i", len(payload)) + payload


def hash_utf16(s: str) -> int:
    """CRC32 of the UTF-16-LE-encoded string (no BOM, no terminator)."""
    return zlib.crc32(s.encode("utf-16-le")) & 0xFFFFFFFF


def build_namespace_table(namespaces: list[tuple[str, list[tuple[str, str]]]]) -> tuple[bytes, list[str], list[int]]:
    """Build the namespace-table bytes + the dedup'd strings array data.

    Returns `(ns_bytes, strings, refcounts)` where `strings` is the
    insertion-ordered list of unique source strings and `refcounts[i]`
    is the count of `(namespace, key)` pairs referencing `strings[i]`.
    """
    # Strings array: deduplicated by exact string content across all namespaces.
    string_to_index: dict[str, int] = {}
    refcounts: list[int] = []
    for _, keys in namespaces:
        for _, value in keys:
            if value not in string_to_index:
                string_to_index[value] = len(string_to_index)
                refcounts.append(0)
            refcounts[string_to_index[value]] += 1
    strings = list(string_to_index.keys())

    ns_bytes = b""
    for namespace, keys in namespaces:
        ns_bytes += struct.pack("<I", hash_utf16(namespace))           # NamespaceHash
        ns_bytes += fstring_ascii(namespace)                            # Namespace FString
        ns_bytes += struct.pack("<I", len(keys))                        # NumKeys
        for key, value in keys:
            ns_bytes += struct.pack("<I", hash_utf16(key))              # KeyHash
            ns_bytes += fstring_ascii(key)                              # Key FString
            ns_bytes += struct.pack("<I", hash_utf16(value))            # SourceStringHash
            ns_bytes += struct.pack("<i", string_to_index[value])       # StringIndex

    return ns_bytes, strings, refcounts


def main() -> None:
    ns_bytes, strings, refcounts = build_namespace_table(NAMESPACES)

    total_entries = sum(len(keys) for _, keys in NAMESPACES)

    # Header through namespace table. StringsArrayOffset (bytes 17..24)
    # is patched in below after the offset is known.
    header_bytes = (
        MAGIC                                            # 0..15
        + bytes([VERSION])                               # 16
        + b"\x00" * 8                                    # 17..24  (StringsArrayOffset placeholder)
        + struct.pack("<I", total_entries)               # 25..28  EntriesCount
        + struct.pack("<I", len(NAMESPACES))             # 29..32  NumNamespaces
        + ns_bytes
    )

    strings_array_offset = len(header_bytes)
    header_bytes = (
        header_bytes[:17]
        + struct.pack("<q", strings_array_offset)
        + header_bytes[25:]
    )

    # Strings array: i32 NumStrings, then per-entry (FString + i32 RefCount).
    strings_payload = struct.pack("<i", len(strings))
    for s, rc in zip(strings, refcounts):
        strings_payload += fstring_ascii(s)
        strings_payload += struct.pack("<i", rc)

    sys.stdout.buffer.write(header_bytes + strings_payload)


if __name__ == "__main__":
    main()
