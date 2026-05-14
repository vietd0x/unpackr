"""Handler for 7-Zip self-extracting archives (detect only).

A 7-Zip SFX is the standard ``7zSD.sfx`` (or similar) stub PE concatenated
with a 7-Zip archive. The archive starts with the 6-byte 7z signature::

    37 7A BC AF 27 1C

The signature appears past the end of the PE image. We confirm it really is
SFX (not just a bundled 7z dependency) by checking that the file is a PE and
that the signature sits in the trailing overlay.

Extraction is one ``7z x <file>`` away — no custom parser needed.
"""
from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..pe import pe_machine
from ..registry import register_handler


SEVENZ_SIGNATURE = b"\x37\x7A\xBC\xAF\x27\x1C"


def _pe_image_end(view: bytes) -> Optional[int]:
    """Return the byte offset where the PE image ends on disk, or None."""
    if len(view) < 0x40 or view[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", view, 0x3C)[0]
    if view[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    num_sections = struct.unpack_from("<H", view, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", view, e_lfanew + 20)[0]
    sect_off = e_lfanew + 24 + size_opt
    end = 0
    for i in range(num_sections):
        raw_off = struct.unpack_from("<I", view, sect_off + i * 40 + 20)[0]
        raw_sz = struct.unpack_from("<I", view, sect_off + i * 40 + 16)[0]
        end = max(end, raw_off + raw_sz)
    return end


class SevenZipSFXHandler(Handler):
    name = "7z-sfx"
    description = "7-Zip self-extracting archive (detect only; unpack via 7z)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            arch = pe_machine(v[:0x1000])
            if arch is None:
                return None  # 7-Zip SFX is always a PE wrapper
            image_end = _pe_image_end(bytes(v[:0x1000]))
            if image_end is None:
                return None
            # Look for the 7z magic only in the overlay region.
            sz_pos = v.find(SEVENZ_SIGNATURE, image_end)
            if sz_pos == -1:
                return None
            payload_size = len(v) - sz_pos

        return Detection(
            handler=self.name,
            confidence="high",
            summary=f"7-Zip SFX ({arch}); 7z archive @ 0x{sz_pos:x}",
            metadata={
                "pe_arch": arch,
                "pe_image_end": image_end,
                "archive_offset": sz_pos,
                "archive_size": payload_size,
                "extraction_hint": "7z x <file>",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(SevenZipSFXHandler())
