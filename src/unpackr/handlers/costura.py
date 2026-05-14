"""Handler for Costura.Fody-embedded .NET assemblies (detect only).

Costura.Fody is a Fody add-in that packs referenced assemblies as gzip-
compressed resources inside the target .NET assembly. Resource names follow
the convention::

    costura.<assemblyname>.dll.compressed
    costura.<assemblyname>.dll
    costura.assemblyloader.dll          # the bootstrap loader

We detect by searching for these resource-name fragments in the file. The
canonical extractor is ``Costura-Decompressor`` (open-source) or ILSpy's
"Save All Resources" feature.
"""
from __future__ import annotations

import mmap
import re
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..registry import register_handler


_COSTURA_TAG = b"costura."
_COSTURA_LOADER = b"costura.AssemblyLoader"
_RESOURCE_RE = re.compile(rb"costura\.[A-Za-z0-9_.\-]{2,80}\.dll(?:\.compressed)?")


class CosturaHandler(Handler):
    name = "costura"
    description = "Costura.Fody-embedded .NET assemblies (detect only)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            tag_pos = v.find(_COSTURA_TAG)
            loader_pos = v.find(_COSTURA_LOADER)
            if tag_pos == -1 and loader_pos == -1:
                return None

            resources = sorted({
                m.group(0).decode("utf-8", "replace")
                for m in _RESOURCE_RE.finditer(v)
            })

        if not resources and loader_pos == -1:
            return None

        return Detection(
            handler=self.name,
            confidence="high" if loader_pos != -1 or len(resources) >= 2 else "medium",
            summary=f"Costura.Fody packed .NET ({len(resources)} embedded assemblies)",
            metadata={
                "loader_present": loader_pos != -1,
                "resources": resources[:32],   # cap so output stays readable
                "resource_count": len(resources),
                "extraction_hint":
                    "Costura-Decompressor or ILSpy -> Save All Resources, "
                    "then gunzip each .compressed entry.",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(CosturaHandler())
