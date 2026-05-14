"""Handler for AutoIt-compiled scripts (detect only).

AutoIt's ``Aut2Exe`` packs the compiled script as a resource named
``SCRIPT`` or appends it to the PE. The payload is prefixed by one of
several magic tags depending on the AutoIt version::

    "AU3!EA05"     # AutoIt 3, older (encrypted)
    "AU3!EA06"     # AutoIt 3.26+
    "FILE"         # internal entry tag inside the payload
    "JB01"         # MSZIP-compressed entry
    "EB01"         # similar

Extraction is delegated to ``Exe2Aut`` / ``myAut2Exe`` which know the
encryption keys and entry format. Reimplementing here would be a few hundred
lines for marginal benefit.
"""
from __future__ import annotations

import mmap
import re
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


_MAGICS = [
    (b"AU3!EA06", "3.26+"),
    (b"AU3!EA05", "3.x older"),
]
_AUXILIARY_STRINGS = [b">>>AUTOIT SCRIPT<<<", b"AutoIt v3", b"AutoIt3.exe"]


class AutoItHandler(Handler):
    name = "autoit"
    description = "AutoIt-compiled script (detect only; unpack via Exe2Aut)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            payload_offset = None
            variant = None
            for magic, ver in _MAGICS:
                pos = v.find(magic)
                if pos != -1:
                    payload_offset = pos
                    variant = ver
                    break
            aux_hits = [s.decode("ascii", "replace") for s in _AUXILIARY_STRINGS if v.find(s) != -1]

        if payload_offset is None and not aux_hits:
            return None

        confidence = "high" if payload_offset is not None else "medium"
        if payload_offset is None:
            summary = "AutoIt-compiled script (heuristic: AutoIt strings present)"
        else:
            summary = f"AutoIt-compiled script (AU3 EA0{variant})"

        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata={
                "payload_offset": payload_offset,
                "variant": variant,
                "auxiliary_strings": aux_hits,
                "extraction_hint": "Exe2Aut / myAut2Exe",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(AutoItHandler())
