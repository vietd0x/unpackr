"""Handler for Java launcher wrappers — install4j, Launch4j, exe4j, JSmooth.

Native EXE that bootstraps a bundled JRE / JAR. Identification leans on
product-specific tag strings, then on the presence of an appended JAR
archive (``PK\\x03\\x04`` in the overlay).

Detect only. Extraction is usually trivial: a JAR is a Zip, and ``7z x``
works on the exe directly for install4j/Launch4j builds.
"""
from __future__ import annotations

import mmap
import re
import struct
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..pe import pe_machine
from ..registry import register_handler


# Product -> list of ascii markers (any-of). Ordered by specificity.
_PRODUCTS: list[tuple[str, list[bytes]]] = [
    ("install4j", [b"install4j", b"com.install4j", b"i4jruntime"]),
    ("Launch4j",  [b"Launch4j", b"net.sf.launch4j"]),
    ("exe4j",     [b"exe4j", b"com.exe4j"]),
    ("JSmooth",   [b"JSmooth", b"jsmooth-"]),
    ("JPackage",  [b"jpackage", b"jdk.jpackage"]),
    ("WinRun4J",  [b"WinRun4J"]),
]

ZIP_LOCAL_HEADER = b"PK\x03\x04"


def _has_appended_jar(view: mmap.mmap) -> Optional[int]:
    """Return the first ZIP local-header offset that lies in the overlay."""
    if len(view) < 0x40 or bytes(view[:2]) != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", view, 0x3C)[0]
    if bytes(view[e_lfanew:e_lfanew + 4]) != b"PE\x00\x00":
        return None
    num_sections = struct.unpack_from("<H", view, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", view, e_lfanew + 20)[0]
    sect_off = e_lfanew + 24 + size_opt
    image_end = 0
    for i in range(num_sections):
        raw_off = struct.unpack_from("<I", view, sect_off + i * 40 + 20)[0]
        raw_sz = struct.unpack_from("<I", view, sect_off + i * 40 + 16)[0]
        image_end = max(image_end, raw_off + raw_sz)
    pos = view.find(ZIP_LOCAL_HEADER, image_end)
    return pos if pos != -1 else None


class JavaWrapperHandler(Handler):
    name = "java-wrapper"
    description = "Java app wrapped in EXE (install4j/Launch4j/exe4j/JSmooth)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            product_hits: list[str] = []
            for name, markers in _PRODUCTS:
                if any(v.find(m) != -1 for m in markers):
                    product_hits.append(name)
            jar_offset = _has_appended_jar(v)
            arch = pe_machine(v[:0x1000])

        if not product_hits and jar_offset is None:
            return None
        if not product_hits:
            # Unknown wrapper but with embedded ZIP/JAR — note it tentatively.
            product_hits = ["unknown-java-wrapper"]
            confidence = "low"
        else:
            confidence = "high"

        summary = f"Java wrapper ({', '.join(product_hits)})"
        if jar_offset is not None:
            summary += f"; embedded JAR @ 0x{jar_offset:x}"

        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata={
                "products": product_hits,
                "embedded_jar_offset": jar_offset,
                "pe_arch": arch,
                "extraction_hint":
                    "7z x <file>   # works for install4j/Launch4j/exe4j; "
                    "or rename .jar and unzip.",
            },
            can_list=False,
            can_extract=False,
        )


register_handler(JavaWrapperHandler())
