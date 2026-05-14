"""Handler for Nuitka-compiled Python executables (detect only).

Nuitka builds either a *standalone* directory or a *onefile* executable. Both
embed distinctive strings produced by Nuitka's code generator. We look for
several markers because individual ones can be stripped — any hit wins.

Markers (ordered by reliability):

* ``__nuitka_init_pyfilenames``   — exported by Nuitka-generated objects
* ``NUITKA_ONEFILE_PARENT``       — env var the OneFile bootstrap sets
* ``KA.\\xfa`` payload prefix     — start-of-attached-archive marker in OneFile
* ``Compiled by Nuitka``          — PE VersionInfo comment in some builds

Extraction is not implemented: the OneFile payload uses zstd compression and
a per-version archive format. ``nuitka-project`` ships ``nuitka --unpack`` for
this; out of scope here.
"""
from __future__ import annotations

import mmap
import re
import struct
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


_BYTE_MARKERS = [
    b"__nuitka_init_pyfilenames",
    b"NUITKA_ONEFILE_PARENT",
    b"Nuitka-Plugins",
    b"nuitka-onefile",
]
# OneFile attached-archive prefix: "KA" + 2-byte version + 4-byte zero pad
# observed in builds since Nuitka 2.x
_ONEFILE_PREFIX_RE = re.compile(rb"KA\x01\x09|KA\x02\x09")


class NuitkaHandler(Handler):
    name = "nuitka"
    description = "Nuitka-compiled Python executable (detect only)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            hits = []
            for m in _BYTE_MARKERS:
                pos = v.find(m)
                if pos != -1:
                    hits.append((m.decode("ascii", "replace"), pos))

            onefile_match = _ONEFILE_PREFIX_RE.search(v)
            onefile_offset = onefile_match.start() if onefile_match else None

        if not hits and onefile_offset is None:
            return None

        confidence = "high" if len(hits) >= 2 or onefile_offset is not None else "medium"
        mode = "OneFile" if onefile_offset is not None else "standalone/embedded"
        summary = f"Nuitka-compiled Python ({mode})"

        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata={
                "markers": hits,
                "onefile_payload_offset": onefile_offset,
                "extraction_hint": "Run the binary with NUITKA_ONEFILE_PARENT=0 "
                                   "to let it self-extract to a temp dir, then "
                                   "inspect the extracted folder.",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(NuitkaHandler())
