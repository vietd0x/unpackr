"""Handler for NSIS-built installers (detect only).

NSIS installers attach a payload right after the bootstrap PE. The payload
begins with a 16-byte ``firstheader`` whose hallmark is::

    EF BE AD DE          # int32 siginfo = 0xDEADBEEF (LE)
    4E 75 6C 6C          # 'N' 'u' 'l' 'l'
    73 6F 66 74          # 's' 'o' 'f' 't'
    49 6E 73 74          # 'I' 'n' 's' 't'

Together: ``"\\xef\\xbe\\xad\\xde Null soft Inst"`` (no space — joined).

Extraction is delegated: ``7-Zip`` (>= 9.38) and ``nsiunpacker`` can list and
unpack the embedded files; reimplementing NSIS' bytecode is out of scope.
"""
from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


NSIS_SIGNATURE = bytes.fromhex("efbeaddeNullsoftInst".encode("ascii").hex())
# Actually build it explicitly to avoid mistakes:
NSIS_SIGNATURE = b"\xef\xbe\xad\xde" + b"NullsoftInst"
assert len(NSIS_SIGNATURE) == 16


class NSISHandler(Handler):
    name = "nsis"
    description = "Nullsoft NSIS installer (detect only; unpack via 7-Zip)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            sig_pos = v.find(NSIS_SIGNATURE)
            if sig_pos == -1:
                return None
            # The 4 bytes before siginfo are flags; following 8 bytes are
            # header_size and total_data_length.
            flags = None
            header_size = total_length = None
            try:
                flags = struct.unpack_from("<I", v, sig_pos - 4)[0]
                header_size, total_length = struct.unpack_from("<II", v, sig_pos + 16)
            except struct.error:
                pass

        return Detection(
            handler=self.name,
            confidence="high",
            summary=f"NSIS installer (payload @ 0x{sig_pos - 4:x})",
            metadata={
                "firstheader_offset": sig_pos - 4,
                "signature_offset": sig_pos,
                "flags": flags,
                "header_size": header_size,
                "total_length": total_length,
                "extraction_hint": "7z x <file>   # or `nsiunpacker`",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(NSISHandler())
