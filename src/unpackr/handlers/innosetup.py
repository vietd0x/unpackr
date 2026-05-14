"""Handler for Inno Setup installers (detect only).

Inno Setup wraps a "setup loader" stub PE with an attached ``setup.0`` /
``setup-N.bin`` payload. Identification:

* ASCII tag ``"Inno Setup Setup Data ("`` appears as a literal string in the
  loader, followed by the engine version (e.g. ``"6.2.1"``).
* The loader's resource ``DVCLAL`` (Delphi compiler licence atom) is almost
  always present.

Extraction is delegated: ``innounp`` reads any Inno Setup version produced
since 2.x and writes the contained files. Implementing the LZMA + script
bytecode parser ourselves would duplicate ~3 kLOC for limited gain.
"""
from __future__ import annotations

import mmap
import re
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


_TAG_RE = re.compile(rb"Inno Setup Setup Data \((\d+\.\d+\.\d+(?:[a-z]\d*)?)\)")
_LOADER_TAG = b"Inno Setup Setup Data"
_RESOURCE_TAG = b"DVCLAL"


class InnoSetupHandler(Handler):
    name = "innosetup"
    description = "Inno Setup installer (detect only; unpack via innounp)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            tag_pos = v.find(_LOADER_TAG)
            has_dvclal = v.find(_RESOURCE_TAG) != -1
            if tag_pos == -1 and not has_dvclal:
                return None

            version_match = _TAG_RE.search(v)
            version = version_match.group(1).decode() if version_match else None

            # The loader stub appends the actual installer payload starting at
            # a well-known offset stored just after the tag. Capture roughly
            # where it sits for the user.
            payload_hint = None
            if tag_pos != -1:
                payload_hint = tag_pos

        if tag_pos == -1:
            confidence = "low"
            summary = "Inno Setup (Delphi loader heuristic only)"
        else:
            confidence = "high"
            summary = f"Inno Setup installer{(' v' + version) if version else ''}"

        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata={
                "version": version,
                "loader_tag_offset": payload_hint,
                "has_dvclal_resource": has_dvclal,
                "extraction_hint": "innounp -x <file>   # https://innounp.sf.net",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(InnoSetupHandler())
