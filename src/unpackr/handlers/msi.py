"""Handler for Windows Installer (MSI) databases (detect only).

MSI files are Microsoft OLE Compound Document File (CDF) containers. The
8-byte CDF magic is shared with legacy Office documents (``.doc``, ``.xls``,
``.ppt``) so we disambiguate by looking for MSI-specific stream-name
fragments inside the file:

* ``\\x05SummaryInformation``   — present in every CDF but with MSI-specific
                                  template GUID.
* ``\\x05DocumentSummaryInformation`` — same.
* MSI tables encoded in the CDF directory entries (UTF-16LE, MIME-style
  base64-like alphabet). The most common signal is the literal substring
  ``"Microsoft Windows Installer"`` or the table name encoding for
  ``"_Tables"``, ``"_StringPool"``, ``"_StringData"``.

Extraction: ``msiextract``, ``lessmsi``, or ``7z x`` (recent versions).
"""
from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


CDF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# MSI table-name encoding uses a base64-like 6-bit alphabet packed into
# UTF-16LE words. We don't need to decode it — we just search for the well-
# known indicator strings.
_MSI_INDICATORS = [
    b"M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 "
    b"\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00I\x00n\x00s\x00t\x00a\x00l\x00l\x00e\x00r\x00",
    b"Microsoft Windows Installer",
    b".msi",                        # common in summary stream
]


class MSIHandler(Handler):
    name = "msi"
    description = "Windows Installer (MSI) database (detect only; unpack via lessmsi)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            if len(v) < 512 or bytes(v[:8]) != CDF_MAGIC:
                return None
            indicators = [s for s in _MSI_INDICATORS if v.find(s) != -1]
            sector_size = struct.unpack_from("<H", v, 0x1E)[0]
            num_dir_sectors = struct.unpack_from("<I", v, 0x28)[0]
            num_fat_sectors = struct.unpack_from("<I", v, 0x2C)[0]

        if not indicators:
            # CDF but not obviously MSI — return a low-confidence hit so the
            # user knows it's at least a CDF document.
            return Detection(
                handler=self.name,
                confidence="low",
                summary="OLE Compound Document (CDF) — could be MSI or Office doc",
                metadata={
                    "is_cdf": True,
                    "sector_size_bytes": 1 << sector_size,
                    "num_dir_sectors": num_dir_sectors,
                    "num_fat_sectors": num_fat_sectors,
                    "extraction_hint":
                        "olefile / 7z l <file>   to list internal streams.",
                },
                can_list=False,
                can_extract=False,
            )

        return Detection(
            handler=self.name,
            confidence="high",
            summary="Windows Installer (MSI) database",
            metadata={
                "is_cdf": True,
                "sector_size_bytes": 1 << sector_size,
                "indicators_found": [
                    s.decode("utf-16-le", "replace") if b"\x00" in s
                    else s.decode("ascii", "replace")
                    for s in indicators
                ],
                "extraction_hint":
                    "lessmsi x <file>   # or `msiextract`, or `7z x` (modern).",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(MSIHandler())
