"""Handler for Xamarin.Android assembly stores.

Xamarin.Android / .NET-for-Android bundles the managed assemblies into a
binary *assembly store* blob that lives inside a native ELF shared library
(``libassemblies.<abi>.so`` / ``libxamarin-app.so``), in an ELF section
named ``payload``.

Layout::

    ELF section "payload"
      +0   uint32 magic            = "XABA" (0x41424158)
      +4   uint32 version          low nibble = store format (2 or 3)
      +8   uint32 entry_count      number of assemblies (= descriptors = names)
      +12  uint32 index_entry_count   hash-index entries (usually 2 * entry_count)
      +16  uint32 index_size
      +20  index entries           (name_hash, descriptor_index[, ignore])
           descriptors             7 * uint32 each (offsets/sizes, blob-relative)
           names                   uint32 length + bytes, one per assembly
           assembly data           optionally LZ4-compressed (see below)

Each assembly's data is either stored raw or prefixed with an ``XALZ`` header::

    +0  "XALZ"                     magic
    +4  uint32 descriptor_index
    +8  uint32 uncompressed_size
    +12 LZ4-block compressed bytes

Detection / parsing ported from XaBlob (https://github.com/Kirlif/XaBlob).
Supports store format version 2 and version 3.
"""
from __future__ import annotations

import mmap
import os
import struct
from pathlib import Path
from typing import Iterable, Optional

from ..core import Detection, Entry, Handler
from ..registry import register_handler


STORE_MAGIC = b"XABA"  # uint32 0x41424158
XALZ_MAGIC = b"XALZ"

# e_machine -> short arch name. Mirrors XaBlob's table.
_ELF_MACHINE = {0x03: "x86", 0x28: "arm", 0x3E: "x64", 0xB7: "arm64"}
_64BIT_ARCH = {"x64", "arm64"}


def _u16(buf, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _find_payload_blob(v) -> Optional[tuple[int, int, bool, str]]:
    """Locate the ``payload`` ELF section.

    Returns ``(blob_offset, blob_size, is64bit, arch)`` or ``None`` when *v*
    is not an ELF we understand or has no ``payload`` section. Never raises.
    """
    try:
        if len(v) < 0x40 or bytes(v[:4]) != b"\x7fELF":
            return None
        ei_class = v[4]  # 1 = ELF32, 2 = ELF64
        arch = _ELF_MACHINE.get(_u16(v, 0x12))
        if arch is None:
            return None
        is64 = ei_class == 2 and arch in _64BIT_ARCH

        e_shoff = _u64(v, 0x28) if is64 else _u32(v, 0x20)
        e_shentsize = _u16(v, 0x3A if is64 else 0x2E)
        e_shnum = _u16(v, 0x3C if is64 else 0x30)
        e_shstrndx = _u16(v, 0x3E if is64 else 0x32)
        section_size = 0x40 if is64 else 0x28

        if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
            return None
        if e_shentsize < section_size:
            return None
        if e_shoff + e_shnum * e_shentsize > len(v):
            return None

        def section(i: int):
            base = e_shoff + i * e_shentsize
            return v[base:base + section_size]

        # Section-header string table tells us each section's name.
        shstr = section(e_shstrndx)
        shstr_off = _u64(shstr, 0x18) if is64 else _u32(shstr, 0x10)
        shstr_sz = _u64(shstr, 0x20) if is64 else _u32(shstr, 0x14)
        if shstr_off + shstr_sz > len(v):
            return None
        strtab = bytes(v[shstr_off:shstr_off + shstr_sz])

        name_idx = strtab.find(b"payload")
        if name_idx == -1:
            return None

        for i in range(e_shnum):
            sh = section(i)
            if _u32(sh, 0) == name_idx:
                blob_offset = _u64(sh, 0x18) if is64 else _u32(sh, 0x10)
                blob_size = _u64(sh, 0x20) if is64 else _u32(sh, 0x14)
                if blob_offset == 0 or blob_offset + blob_size > len(v):
                    return None
                return blob_offset, blob_size, is64, arch
        return None
    except struct.error:
        return None


class _Record:
    """One parsed assembly-store descriptor (offsets are blob-relative)."""

    __slots__ = (
        "name", "mapping_index", "ignore",
        "data_offset", "data_size",
        "debug_offset", "debug_size",
        "config_offset", "config_size",
    )

    def __init__(self, name, ignore, descriptor):
        (self.mapping_index, self.data_offset, self.data_size,
         self.debug_offset, self.debug_size,
         self.config_offset, self.config_size) = descriptor
        self.name = name
        self.ignore = ignore


def _parse_store(blob: bytes, is64: bool) -> list[_Record]:
    """Parse the index/descriptor/name tables out of a store *blob*."""
    magic, version, entry_count, index_entry_count, _index_size = struct.unpack_from(
        "<5I", blob, 0
    )
    has_ignore = (version & 0xF) > 2
    pos = 20

    # Index entries: (name_hash, descriptor_index[, ignore]). We only need the
    # per-descriptor ignore flag; the first entry seen for a descriptor wins.
    ignore_by_desc: dict[int, bool] = {}
    for _ in range(index_entry_count):
        if is64:
            descriptor_index = _u32(blob, pos + 8)
            ignore = bool(blob[pos + 12]) if has_ignore else False
            pos += 13 if has_ignore else 12
        else:
            descriptor_index = _u32(blob, pos + 4)
            ignore = bool(blob[pos + 8]) if has_ignore else False
            pos += 9 if has_ignore else 8
        ignore_by_desc.setdefault(descriptor_index, ignore)

    descriptors = []
    for _ in range(entry_count):
        descriptors.append(struct.unpack_from("<7I", blob, pos))
        pos += 28

    names = []
    for _ in range(entry_count):
        n = _u32(blob, pos)
        pos += 4
        names.append(blob[pos:pos + n].decode("utf-8", "replace"))
        pos += n

    records = []
    for i in range(entry_count):
        records.append(_Record(names[i], ignore_by_desc.get(i, False),
                               descriptors[i]))
    return records


def _pdb_name(name: str) -> str:
    return os.path.splitext(name)[0] + ".pdb"


class XamarinStoreHandler(Handler):
    name = "xamarin-store"
    description = "Xamarin.Android assembly store (libassemblies/libxamarin-app.so)"

    def detect(self, path: Path) -> Optional[Detection]:
        try:
            if path.stat().st_size < 0x40:
                return None
            with path.open("rb") as f:
                if f.read(4) != b"\x7fELF":
                    return None
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
                    found = _find_payload_blob(v)
                    if found is None:
                        return None
                    blob_offset, blob_size, is64, arch = found
                    if blob_size < 20:
                        return None
                    header = bytes(v[blob_offset:blob_offset + 20])
        except (OSError, ValueError):
            return None

        if header[:4] != STORE_MAGIC:
            return None
        version, entry_count, index_entry_count, _index_size = struct.unpack_from(
            "<4I", header, 4
        )
        fmt_ver = version & 0xF
        supported = fmt_ver in (2, 3)

        meta = {
            "store_format_version": fmt_ver,
            "raw_version": version,
            "entry_count": entry_count,
            "index_entry_count": index_entry_count,
            "elf_arch": arch,
            "is64bit": is64,
            "blob_offset": blob_offset,
            "blob_size": blob_size,
        }
        summary = (
            f"Xamarin.Android assembly store v{fmt_ver} "
            f"({arch}, {entry_count} assemblies)"
            + ("" if supported else " - unsupported format version")
        )
        return Detection(
            handler=self.name,
            confidence="high",
            summary=summary,
            metadata=meta,
            can_list=supported,
            can_extract=supported,
        )

    def _load(self, path: Path, detection: Detection) -> tuple[int, bool, list[_Record]]:
        m = detection.metadata
        blob_offset = m["blob_offset"]
        with path.open("rb") as f:
            f.seek(blob_offset)
            blob = f.read(m["blob_size"])
        return blob_offset, blob, _parse_store(blob, m["is64bit"])

    def list_entries(self, path: Path, detection: Detection) -> list[Entry]:
        base, blob, records = self._load(path, detection)
        entries: list[Entry] = []
        for r in records:
            head = blob[r.data_offset:r.data_offset + 12]
            compressed = head[:4] == XALZ_MAGIC
            size = _u32(head, 8) if compressed else r.data_size
            entries.append(Entry(
                name=r.name,
                size=size,
                offset=base + r.data_offset,
                compressed_size=r.data_size if compressed else 0,
                type="Assembly",
                metadata={
                    "mapping_index": r.mapping_index,
                    "ignore": r.ignore,
                    "compressed": compressed,
                },
            ))
            if r.debug_size:
                entries.append(Entry(
                    name=_pdb_name(r.name), size=r.debug_size,
                    offset=base + r.debug_offset, type="Symbols",
                ))
            if r.config_size:
                entries.append(Entry(
                    name=r.name + ".config", size=r.config_size,
                    offset=base + r.config_offset, type="Config",
                ))
        return entries

    def extract(
        self,
        path: Path,
        out_dir: Path,
        detection: Detection,
        *,
        only: Optional[Iterable[str]] = None,
        overwrite: bool = True,
    ) -> list[Path]:
        # lz4 is a declared dependency, but imported lazily so a missing
        # install never breaks handler registration or detect/list.
        decompress = None

        _base, blob, records = self._load(path, detection)
        out_dir.mkdir(parents=True, exist_ok=True)
        name_set = set(only) if only is not None else None
        written: list[Path] = []

        def emit(name: str, payload: bytes) -> None:
            if name_set is not None and not (
                name in name_set or os.path.basename(name) in name_set
            ):
                return
            safe = name.replace("\\", "/").lstrip("/")
            if ".." in safe.split("/"):
                raise ValueError(f"Suspicious entry path: {name!r}")
            out_path = out_dir / safe
            if out_path.exists() and not overwrite:
                return
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(payload)
            written.append(out_path)

        for r in records:
            if r.ignore:
                continue
            data = blob[r.data_offset:r.data_offset + r.data_size]
            if data[:4] == XALZ_MAGIC:
                if decompress is None:
                    try:
                        from lz4.block import decompress as decompress  # noqa: PLC0415
                    except ImportError as e:
                        raise RuntimeError(
                            "Extracting LZ4-compressed Xamarin assemblies "
                            "requires the 'lz4' package: pip install lz4"
                        ) from e
                payload = decompress(data[12:], uncompressed_size=_u32(data, 8))
            else:
                payload = data
            emit(r.name, payload)
            if r.debug_size:
                emit(_pdb_name(r.name),
                     blob[r.debug_offset:r.debug_offset + r.debug_size])
            if r.config_size:
                emit(r.name + ".config",
                     blob[r.config_offset:r.config_offset + r.config_size])
        return written


register_handler(XamarinStoreHandler())
