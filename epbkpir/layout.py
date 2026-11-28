"""Fixed-size block layouts with per-object authenticated encryption.

The AES-256-GCM tag is detached, so ciphertext length equals plaintext length
and q_j = ceil(L_j/B) remains exact.  A locator is a capability: possession of
its key/nonce/tag permits decryption of exactly one logical object.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class LayoutKind(str, Enum):
    ALIGNED = "A"
    COMPACT = "B"


class CapacityExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class Locator:
    logical_index: int
    start_block: int
    start_offset: int
    true_length: int
    block_count: int
    key: bytes
    nonce: bytes
    tag: bytes


@dataclass(frozen=True)
class BlockDatabase:
    block_size: int
    layout: LayoutKind
    blocks: tuple[bytes, ...]
    locators: tuple[Locator, ...]
    dummy_start: int
    dummy_count: int


def read_object_files(paths: Sequence[Path]) -> tuple[bytes, ...]:
    """Read objects in caller-supplied logical order; file names are not encoded."""
    return tuple(path.read_bytes() for path in paths)


def _aad(j: int, length: int) -> bytes:
    return b"BLOCK-OBJECT-v1\x00" + struct.pack(">IQ", j, length)


def encrypt_object(data: bytes, j: int, key: bytes | None = None, nonce: bytes | None = None):
    key = key or os.urandom(32)
    nonce = nonce or os.urandom(12)
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("AES-256-GCM requires 32-byte key and 12-byte nonce")
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_aad(j, len(data)))
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, key, nonce, encryptor.tag


def decrypt_object(ciphertext: bytes, locator: Locator) -> bytes:
    if len(ciphertext) != locator.true_length:
        raise ValueError("ciphertext length does not match locator")
    decryptor = Cipher(
        algorithms.AES(locator.key), modes.GCM(locator.nonce, locator.tag)
    ).decryptor()
    decryptor.authenticate_additional_data(
        _aad(locator.logical_index, locator.true_length)
    )
    return decryptor.update(ciphertext) + decryptor.finalize()


def build_database(
    objects: Sequence[bytes], block_size: int, layout: LayoutKind, dummy_count: int
) -> BlockDatabase:
    if block_size <= 0 or dummy_count < 0:
        raise ValueError("invalid block_size or dummy_count")
    encrypted = [encrypt_object(bytes(value), j) for j, value in enumerate(objects)]
    blocks: list[bytes] = []
    locators: list[Locator] = []

    if layout is LayoutKind.ALIGNED:
        for j, (ciphertext, key, nonce, tag) in enumerate(encrypted):
            start = len(blocks)
            count = math.ceil(len(ciphertext) / block_size) if ciphertext else 0
            for k in range(count):
                piece = ciphertext[k * block_size : (k + 1) * block_size]
                blocks.append(piece + os.urandom(block_size - len(piece)))
            locators.append(Locator(j, start, 0, len(ciphertext), count, key, nonce, tag))
    else:
        stream = bytearray()
        offsets = []
        for ciphertext, *_ in encrypted:
            offsets.append(len(stream))
            stream.extend(ciphertext)
        for start in range(0, len(stream), block_size):
            piece = bytes(stream[start : start + block_size])
            blocks.append(piece + os.urandom(block_size - len(piece)))
        for j, ((ciphertext, key, nonce, tag), absolute) in enumerate(zip(encrypted, offsets)):
            start_block, start_offset = divmod(absolute, block_size)
            count = math.ceil((start_offset + len(ciphertext)) / block_size) if ciphertext else 0
            locators.append(
                Locator(j, start_block, start_offset, len(ciphertext), count, key, nonce, tag)
            )

    dummy_start = len(blocks)
    blocks.extend(os.urandom(block_size) for _ in range(dummy_count))
    return BlockDatabase(
        block_size, layout, tuple(blocks), tuple(locators), dummy_start, dummy_count
    )


def object_block_indices(locator: Locator) -> tuple[int, ...]:
    return tuple(range(locator.start_block, locator.start_block + locator.block_count))


def recover_ciphertext(locator: Locator, returned_blocks: dict[int, bytes], B: int) -> bytes:
    joined = b"".join(returned_blocks[i] for i in object_block_indices(locator))
    return joined[locator.start_offset : locator.start_offset + locator.true_length]


def recover_object(locator: Locator, returned_blocks: dict[int, bytes], B: int) -> bytes:
    return decrypt_object(recover_ciphertext(locator, returned_blocks, B), locator)


def padded_query_indices(
    locators: Sequence[Locator], database: BlockDatabase, Q: int
) -> tuple[int, ...]:
    expanded = [index for locator in locators for index in object_block_indices(locator)]
    # Keep the specified conservative q=sum(q_j) capacity rule.  Compact layout
    # can make adjacent targets share one physical block; query it only once and
    # replace the saved slot by another distinct dummy query.
    if len(expanded) > Q:
        raise CapacityExceeded(f"q={len(expanded)} exceeds Q={Q}")
    real = list(dict.fromkeys(expanded))
    needed = Q - len(real)
    if needed > database.dummy_count:
        raise ValueError("dedicated dummy area is too small")
    dummy = list(range(database.dummy_start, database.dummy_start + needed))
    result = real + dummy
    secrets.SystemRandom().shuffle(result)
    return tuple(result)


_DB_HEADER = struct.Struct("<8sQQ")


def write_block_database(path: Path, database: BlockDatabase) -> None:
    with path.open("wb") as handle:
        handle.write(_DB_HEADER.pack(b"BLKDB1\0\0", database.block_size, len(database.blocks)))
        for block in database.blocks:
            if len(block) != database.block_size:
                raise ValueError("non-uniform block")
            handle.write(block)


def read_block_database(path: Path) -> tuple[int, tuple[bytes, ...]]:
    with path.open("rb") as handle:
        magic, B, count = _DB_HEADER.unpack(handle.read(_DB_HEADER.size))
        if magic != b"BLKDB1\0\0":
            raise ValueError("bad block database magic")
        blocks = tuple(handle.read(B) for _ in range(count))
        if any(len(block) != B for block in blocks) or handle.read(1):
            raise ValueError("truncated or trailing block database data")
    return B, blocks


def pack_payload_slots(block: bytes, bits_per_slot: int = 17) -> tuple[int, ...]:
    """Pack a byte block into PIRANA's fixed-count plaintext slots."""
    mask = (1 << bits_per_slot) - 1
    output = []
    accumulator = 0
    available = 0
    for byte in block:
        accumulator |= byte << available
        available += 8
        while available >= bits_per_slot:
            output.append(accumulator & mask)
            accumulator >>= bits_per_slot
            available -= bits_per_slot
    if available:
        output.append(accumulator)
    return tuple(output)


def unpack_payload_slots(slots: Sequence[int], byte_length: int, bits_per_slot: int = 17) -> bytes:
    output = bytearray()
    accumulator = 0
    available = 0
    for slot in slots:
        accumulator |= int(slot) << available
        available += bits_per_slot
        while available >= 8 and len(output) < byte_length:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            available -= 8
    return bytes(output)


def write_pirana_slot_database(path: Path, database: BlockDatabase) -> None:
    slots = [pack_payload_slots(block) for block in database.blocks]
    slot_count = len(slots[0]) if slots else math.ceil(database.block_size * 8 / 17)
    with path.open("wb") as handle:
        handle.write(struct.pack("<8sQQQ", b"PIRSLOT1", len(slots), database.block_size, slot_count))
        for payload in slots:
            if len(payload) != slot_count:
                raise ValueError("slot count mismatch")
            handle.write(struct.pack(f"<{slot_count}Q", *payload))


def storage_metrics(lengths: Sequence[int], B: int) -> dict[str, float | int]:
    total = sum(lengths)
    maximum = max(lengths, default=0)
    global_max = len(lengths) * maximum
    aligned = sum(math.ceil(length / B) * B for length in lengths)
    compact = math.ceil(total / B) * B if total else 0
    return {
        "raw": total,
        "global_max": global_max,
        "layout_A": aligned,
        "layout_B": compact,
        "global_ratio": global_max / total if total else 1.0,
        "alpha_A": aligned / total if total else 1.0,
        "alpha_B": compact / total if total else 1.0,
    }
