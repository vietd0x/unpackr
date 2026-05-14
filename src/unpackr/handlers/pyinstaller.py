"""Handler for PyInstaller frozen Windows executables.

Detection looks for the archive cookie (magic ``MEI\\x0c\\x0b\\x0a\\x0b\\x0e``)
near the end of the file. Layout (PyInstaller >= 4.0)::

    COOKIE (24 + 64 bytes):
        char     magic[8]       = "MEI\\x0c\\x0b\\x0a\\x0b\\x0e"
        uint32   len            (big-endian)  total archive length
        uint32   TOC            (big-endian)  TOC offset within archive
        uint32   TOClen         (big-endian)
        uint32   pyvers         (big-endian)  e.g. 311 for Python 3.11
        char     pylibname[64]                "python311.dll" / "libpython3.11.so"

    TOC entry (big-endian, variable length, padded to multiple of 8):
        uint32   structlen
        uint32   pos            position within archive
        uint32   len            on-disk (possibly compressed) size
        uint32   ulen           uncompressed size
        uint8    cflag          1 = zlib-compressed
        char     typcmpr        type code: s/m/M/b/x/z/Z/d/...
        char     name[structlen - 18]

Reference: PyInstaller, ``PyInstaller/loader/pyimod02_archive.py``.
"""
from __future__ import annotations

import io
import mmap
import os
import struct
import zlib
from pathlib import Path
from typing import Iterable, Optional

from ..core import Detection, Entry, Handler
from ..registry import register_handler


COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_SIZE = 24 + 64               # magic + 4*u32 + pylibname[64]
TAIL_SEARCH_LIMIT = 8 * 1024 * 1024  # cookie sits near EOF; 8 MB is generous

# Type code → friendly label and whether the entry is "interesting" to a user.
_TYPE_LABEL = {
    "s": "PyZ-Source",       # CArchive of zlib-compressed source
    "m": "Module",
    "M": "PackageInit",
    "b": "Pyc-Module",       # .pyc compiled module
    "x": "Data",
    "z": "PYZ",              # the ZlibArchive (modules)
    "Z": "PyZ-Zip",
    "o": "Option",
    "l": "Splash",
    "d": "Dependency",
    "n": "Symlink",
}


class PyInstallerHandler(Handler):
    name = "pyinstaller"
    description = "PyInstaller frozen executable (CArchive + PYZ)"

    def detect(self, path: Path) -> Optional[Detection]:
        size = path.stat().st_size
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            start = max(0, size - TAIL_SEARCH_LIMIT)
            cookie_pos = v.rfind(COOKIE_MAGIC, start)
            if cookie_pos == -1:
                return None
            if cookie_pos + COOKIE_SIZE > size:
                return None
            cookie = bytes(v[cookie_pos:cookie_pos + COOKIE_SIZE])

        # ints are big-endian inside the cookie
        archive_len, toc_off_rel, toc_len, pyvers = struct.unpack(
            ">IIII", cookie[8:24]
        )
        pylibname = cookie[24:].split(b"\x00", 1)[0].decode("ascii", errors="replace")

        archive_start = cookie_pos + COOKIE_SIZE - archive_len
        if archive_start < 0:
            return None

        py = f"{pyvers // 100}.{pyvers % 100}" if pyvers >= 100 else str(pyvers)
        summary = f"PyInstaller archive (Python {py}, {pylibname or 'unknown lib'})"

        meta = {
            "cookie_offset": cookie_pos,
            "archive_start": archive_start,
            "archive_length": archive_len,
            "toc_offset": archive_start + toc_off_rel,
            "toc_length": toc_len,
            "python_version": py,
            "python_lib": pylibname,
        }
        return Detection(
            handler=self.name,
            confidence="high",
            summary=summary,
            metadata=meta,
            can_list=True,
            can_extract=True,
        )

    def _read_toc(self, path: Path, toc_offset: int, toc_length: int) -> list[Entry]:
        with path.open("rb") as f:
            f.seek(toc_offset)
            toc_bytes = f.read(toc_length)

        entries: list[Entry] = []
        cur = 0
        while cur < len(toc_bytes):
            if cur + 18 > len(toc_bytes):
                break
            structlen = struct.unpack(">I", toc_bytes[cur:cur + 4])[0]
            if structlen < 18 or cur + structlen > len(toc_bytes):
                break
            pos, length, ulen = struct.unpack(">III", toc_bytes[cur + 4:cur + 16])
            cflag = toc_bytes[cur + 16]
            typcmpr = bytes([toc_bytes[cur + 17]]).decode("ascii", errors="replace")
            name = toc_bytes[cur + 18:cur + structlen].rstrip(b"\x00").decode(
                "utf-8", errors="replace"
            )
            entries.append(Entry(
                name=name,
                size=ulen,
                offset=pos,           # relative to archive_start
                compressed_size=length if cflag == 1 else 0,
                type=_TYPE_LABEL.get(typcmpr, f"raw:{typcmpr}"),
                metadata={"cflag": cflag, "typcmpr": typcmpr},
            ))
            cur += structlen
        return entries

    def list_entries(self, path: Path, detection: Detection) -> list[Entry]:
        m = detection.metadata
        return self._read_toc(path, m["toc_offset"], m["toc_length"])

    def extract(
        self,
        path: Path,
        out_dir: Path,
        detection: Detection,
        *,
        only: Optional[Iterable[str]] = None,
        overwrite: bool = True,
    ) -> list[Path]:
        m = detection.metadata
        archive_start = m["archive_start"]
        entries = self._read_toc(path, m["toc_offset"], m["toc_length"])

        out_dir.mkdir(parents=True, exist_ok=True)
        name_set = set(only) if only is not None else None
        written: list[Path] = []

        with path.open("rb") as f:
            for entry in entries:
                if name_set is not None and not (
                    entry.name in name_set
                    or os.path.basename(entry.name) in name_set
                ):
                    continue

                safe = entry.name.replace("\\", "/").lstrip("/")
                if ".." in safe.split("/"):
                    raise ValueError(f"Suspicious entry path: {entry.name!r}")

                # PyInstaller TOC uses bare module names; add .pyc for module types
                if entry.type in ("Module", "PackageInit", "Pyc-Module") and not safe.endswith(".pyc"):
                    safe += ".pyc"

                out_path = out_dir / safe
                if out_path.exists() and not overwrite:
                    continue
                out_path.parent.mkdir(parents=True, exist_ok=True)

                f.seek(archive_start + entry.offset)
                read_len = entry.compressed_size or entry.size
                data = f.read(read_len)
                if entry.is_compressed:
                    data = zlib.decompress(data)
                out_path.write_bytes(data)
                written.append(out_path)

        return written


register_handler(PyInstallerHandler())
