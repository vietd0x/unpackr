"""Round-trip tests for the Xamarin assembly-store handler.

There is no real ``libassemblies.so`` checked into the repo, so we synthesize
a minimal but valid ELF whose ``payload`` section holds a v2 assembly store
with one raw and one LZ4-compressed (``XALZ``) assembly, then drive
detect/list/extract through the public API.
"""
from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import lz4.block

from unpackr import get_handler, probe


STORE_MAGIC = 0x41424158  # "XABA"


def _build_store_v2_64(assemblies):
    """assemblies: list of (name, data_bytes, debug_bytes, config_bytes)."""
    entry_count = len(assemblies)
    index_entry_count = 2 * entry_count
    index_bytes = index_entry_count * 12          # <QI> per entry (v2, 64-bit)
    desc_bytes = entry_count * 28                 # <7I> per descriptor
    name_blobs = [struct.pack("<I", len(n.encode())) + n.encode()
                  for n, _, _, _ in assemblies]
    data_start = 20 + index_bytes + desc_bytes + sum(len(b) for b in name_blobs)

    descriptors = []
    data_region = bytearray()
    cur = data_start
    for _name, data, debug, config in assemblies:
        d_off, d_sz = cur, len(data)
        data_region += data
        cur += d_sz
        if debug:
            dbg_off, dbg_sz = cur, len(debug)
            data_region += debug
            cur += dbg_sz
        else:
            dbg_off = dbg_sz = 0
        if config:
            cfg_off, cfg_sz = cur, len(config)
            data_region += config
            cur += cfg_sz
        else:
            cfg_off = cfg_sz = 0
        descriptors.append((d_off, d_sz, dbg_off, dbg_sz, cfg_off, cfg_sz))

    out = bytearray()
    out += struct.pack("<5I", STORE_MAGIC, 2, entry_count, index_entry_count, 0)
    for i in range(entry_count):                  # two hash entries per descriptor
        out += struct.pack("<QI", 0x1000 + 2 * i, i)
        out += struct.pack("<QI", 0x1001 + 2 * i, i)
    for i, d in enumerate(descriptors):
        out += struct.pack("<7I", i, *d)          # descriptor[0] = mapping_index
    for b in name_blobs:
        out += b
    out += data_region
    assert len(out) - len(data_region) == data_start
    return bytes(out)


def _build_elf64_arm64(blob: bytes) -> bytes:
    shstrtab = b"\x00payload\x00.shstrtab\x00"
    payload_name = shstrtab.index(b"payload")
    shstr_name = shstrtab.index(b".shstrtab")

    blob_off = 64
    shstrtab_off = blob_off + len(blob)
    shoff = shstrtab_off + len(shstrtab)

    def shdr(name_off, sh_type, offset, size):
        h = bytearray(0x40)
        struct.pack_into("<I", h, 0x00, name_off)
        struct.pack_into("<I", h, 0x04, sh_type)
        struct.pack_into("<Q", h, 0x18, offset)
        struct.pack_into("<Q", h, 0x20, size)
        return bytes(h)

    shtable = (bytes(0x40)                                   # SHN_UNDEF
               + shdr(payload_name, 1, blob_off, len(blob))  # payload
               + shdr(shstr_name, 3, shstrtab_off, len(shstrtab)))

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2          # ELFCLASS64
    ehdr[5] = 1          # little endian
    struct.pack_into("<H", ehdr, 0x12, 0xB7)   # EM_AARCH64
    struct.pack_into("<Q", ehdr, 0x28, shoff)  # e_shoff
    struct.pack_into("<H", ehdr, 0x3A, 0x40)   # e_shentsize
    struct.pack_into("<H", ehdr, 0x3C, 3)      # e_shnum
    struct.pack_into("<H", ehdr, 0x3E, 2)      # e_shstrndx
    return bytes(ehdr) + blob + shstrtab + shtable


def _xalz(payload: bytes, index: int) -> bytes:
    # "XALZ" + uint32 descriptor_index + lz4.block.compress(...) where the
    # compressor's own 4-byte size prefix doubles as the uncompressed length.
    return b"XALZ" + struct.pack("<I", index) + lz4.block.compress(payload)


RAW = b"PLAIN-HELLO-ASSEMBLY-BODY"
WORLD = b"DECOMPRESSED-WORLD-ASSEMBLY-" * 8   # compresses well
CONFIG = b"<configuration><appSettings/></configuration>"


def _make_sample() -> Path:
    store = _build_store_v2_64([
        ("Hello.dll", RAW, b"", CONFIG),
        ("World.dll", _xalz(WORLD, 1), b"", b""),
    ])
    elf = _build_elf64_arm64(store)
    tmp = Path(tempfile.mkdtemp(prefix="xablob_")) / "libassemblies.arm64-v8a.so"
    tmp.write_bytes(elf)
    return tmp


def test_detect():
    sample = _make_sample()
    matches = probe(sample)
    by_name = {h.name: d for h, d in matches}
    assert "xamarin-store" in by_name
    d = by_name["xamarin-store"]
    assert d.confidence == "high"
    assert d.can_list and d.can_extract
    assert d.metadata["store_format_version"] == 2
    assert d.metadata["entry_count"] == 2
    assert d.metadata["elf_arch"] == "arm64"
    assert d.metadata["is64bit"] is True


def test_list_entries():
    sample = _make_sample()
    h = get_handler("xamarin-store")
    d = h.detect(sample)
    entries = h.list_entries(sample, d)
    by_name = {e.name: e for e in entries}

    assert by_name["Hello.dll"].size == len(RAW)
    assert by_name["Hello.dll"].compressed_size == 0
    assert by_name["Hello.dll"].metadata["compressed"] is False

    world = by_name["World.dll"]
    assert world.metadata["compressed"] is True
    assert world.size == len(WORLD)               # decompressed size
    assert world.compressed_size > 0              # stored (XALZ) size

    assert "Hello.dll.config" in by_name
    assert by_name["Hello.dll.config"].size == len(CONFIG)


def test_extract_roundtrip():
    sample = _make_sample()
    h = get_handler("xamarin-store")
    d = h.detect(sample)
    out = sample.parent / "unpacked"
    written = h.extract(sample, out, d)

    assert (out / "Hello.dll").read_bytes() == RAW
    assert (out / "World.dll").read_bytes() == WORLD       # LZ4-decompressed
    assert (out / "Hello.dll.config").read_bytes() == CONFIG
    assert {p.name for p in written} >= {"Hello.dll", "World.dll", "Hello.dll.config"}


def test_extract_only_filter():
    sample = _make_sample()
    h = get_handler("xamarin-store")
    d = h.detect(sample)
    out = sample.parent / "unpacked_only"
    written = h.extract(sample, out, d, only=["World.dll"])
    names = {p.name for p in written}
    assert names == {"World.dll"}
    assert (out / "World.dll").read_bytes() == WORLD


def test_non_xamarin_returns_none():
    h = get_handler("xamarin-store")
    # A PE file (notepad) and a plain text file must not match and must not throw.
    notepad = Path(r"C:\Windows\notepad.exe")
    if notepad.exists():
        assert h.detect(notepad) is None
    txt = Path(tempfile.mkdtemp(prefix="xablob_")) / "x.txt"
    txt.write_bytes(b"not an elf at all, just some bytes" * 4)
    assert h.detect(txt) is None


if __name__ == "__main__":
    test_detect()
    test_list_entries()
    test_extract_roundtrip()
    test_extract_only_filter()
    test_non_xamarin_returns_none()
    print("OK - all xamarin handler tests passed")
