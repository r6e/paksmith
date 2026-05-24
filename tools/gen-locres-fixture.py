#!/usr/bin/env python3
"""Generate a minimal .locres v2 (Optimized_CRC32) fixture for documentation.

Wire format per `docs/formats/data/locres.md`. Emits exactly 124 bytes:

  - 16-byte magic FGuid
  - 1-byte version (0x02 = Optimized_CRC32)
  - 8-byte i64 StringsArrayOffset (LE)
  - 4-byte u32 EntriesCount (LE; v2+ only)
  - Namespace table (1 namespace with 2 keys)
  - Strings array at the offset (2 unique strings, each with RefCount=1)

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


def fstring_ascii(s: str) -> bytes:
    """Serialize ASCII string as UE FString: i32 length (incl. null) + bytes + null."""
    payload = s.encode("ascii") + b"\x00"
    return struct.pack("<i", len(payload)) + payload


def hash_utf16(s: str) -> int:
    """CRC32 of the UTF-16-LE-encoded string (no BOM, no terminator)."""
    return zlib.crc32(s.encode("utf-16-le")) & 0xFFFFFFFF


def main() -> None:
    namespace = "Game"
    keys = [("key1", "Hello"), ("key2", "World")]

    # Strings array: deduplicated source strings.
    string_to_index = {}
    for _, value in keys:
        if value not in string_to_index:
            string_to_index[value] = len(string_to_index)
    strings = list(string_to_index.keys())  # preserves insertion order
    refcounts = [
        sum(1 for _, v in keys if v == s) for s in strings
    ]

    # Build namespace table (everything BEFORE the strings array).
    ns_bytes = b""
    ns_bytes += struct.pack("<I", hash_utf16(namespace))   # NamespaceHash
    ns_bytes += fstring_ascii(namespace)                    # Namespace FString
    ns_bytes += struct.pack("<I", len(keys))                # NumKeys
    for key, value in keys:
        ns_bytes += struct.pack("<I", hash_utf16(key))      # KeyHash
        ns_bytes += fstring_ascii(key)                      # Key FString
        ns_bytes += struct.pack("<I", hash_utf16(value))    # SourceStringHash
        ns_bytes += struct.pack("<i", string_to_index[value])  # StringIndex

    # Header through namespace table (header = 25 bytes, EntriesCount = 4,
    # NumNamespaces = 4, then ns_bytes).
    header_bytes = (
        MAGIC                                                   # 0..15
        + bytes([VERSION])                                      # 16
        # StringsArrayOffset placeholder, filled in after we know the offset.
        + b"\x00" * 8                                           # 17..24
        + struct.pack("<I", sum(len(ks) for ks in [keys]))      # EntriesCount; 25..28
        + struct.pack("<I", 1)                                  # NumNamespaces; 29..32
        + ns_bytes
    )

    strings_array_offset = len(header_bytes)

    # Patch StringsArrayOffset (i64 LE at bytes 17..24).
    header_bytes = (
        header_bytes[:17]
        + struct.pack("<q", strings_array_offset)
        + header_bytes[25:]
    )

    # Strings array: NumStrings (i32), then per-entry FString + RefCount.
    strings_payload = struct.pack("<i", len(strings))
    for s, rc in zip(strings, refcounts):
        strings_payload += fstring_ascii(s)
        strings_payload += struct.pack("<i", rc)

    sys.stdout.buffer.write(header_bytes + strings_payload)


if __name__ == "__main__":
    main()
