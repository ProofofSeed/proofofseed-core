

def parse_words(blob: bytes) -> tuple[bytes, list[int], list[int]]:
    """Split a serialized circuit output into its `(u8, u32, u64)` sections.

    The wire form is three sections, each a two-byte big-endian count followed by that
    many little-endian values (`proofofseed_circuits::serialize_words`). Parsing it is the
    only way to compare a circuit's output with an independently computed value: the
    sections are not in a fixed order relative to the semantic payload, and the trailing
    assertion word the backend emits lands in the u8 section, not at the end of the blob.
    """
    at = 0

    def count() -> int:
        nonlocal at
        n = int.from_bytes(blob[at:at + 2], "big")
        at += 2
        return n

    n8 = count()
    u8 = blob[at:at + n8]
    at += n8
    n32 = count()
    u32 = [int.from_bytes(blob[at + 4 * i:at + 4 * i + 4], "little") for i in range(n32)]
    at += 4 * n32
    n64 = count()
    u64 = [int.from_bytes(blob[at + 8 * i:at + 8 * i + 8], "little") for i in range(n64)]
    at += 8 * n64
    if at != len(blob):
        raise ValueError(f"{len(blob) - at} trailing bytes after the three sections")
    return u8, u32, u64


def be_from_limbs(limbs: list[int]) -> bytes:
    """Reassemble little-endian-first u64 limbs into a big-endian byte string."""
    return b"".join(limb.to_bytes(8, "big") for limb in reversed(limbs))
