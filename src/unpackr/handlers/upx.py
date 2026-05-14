"""Handler for UPX-packed PE binaries (detect-only).

UPX leaves three telltales:

* Section names ``UPX0``, ``UPX1`` (and sometimes ``UPX2``) — the original
  PE sections are replaced by the unpacker stub + compressed payload.
* The literal banner ``"$Info: This file is packed with the UPX..."`` in
  ``UPX1``.
* The ASCII tag ``"UPX!"`` at the start of the packed header.

Extraction is delegated to the upstream ``upx -d`` binary (``upx_version``
is reported when available). Reimplementing the unpacker is out of scope —
it would mean shipping the entire NRV/LZMA reference decoders.
"""
from __future__ import annotations

import mmap
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from ..core import Detection, Handler, UnsupportedOperation
from ..pe import pe_section_names
from ..registry import register_handler


_UPX_BANNER_RE = re.compile(
    rb"\$Info:\s+This file is packed with the UPX[^\x00]*?UPX\s+(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE | re.DOTALL,
)


class UpxHandler(Handler):
    name = "upx"
    description = "UPX-packed PE (detect only; extract via `upx -d`)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            section_names = pe_section_names(v[:0x1000])
            has_upx_sections = any(n.startswith("UPX") for n in section_names)
            has_tag = bytes(v[:0x4000]).find(b"UPX!") != -1 or v.find(b"UPX!") != -1
            banner = _UPX_BANNER_RE.search(v)

        if not (has_upx_sections or has_tag or banner):
            return None

        if has_upx_sections and (banner or has_tag):
            confidence = "high"
        elif has_upx_sections or banner:
            confidence = "medium"
        else:
            confidence = "low"

        upx_version = banner.group(1).decode() if banner else None

        meta = {
            "sections": section_names,
            "upx_sections": [n for n in section_names if n.startswith("UPX")],
            "banner_found": banner is not None,
            "upx_version": upx_version,
            "upx_d_available": shutil.which("upx") is not None,
        }
        ver = f" v{upx_version}" if upx_version else ""
        summary = f"UPX-packed PE{ver} (extract with `upx -d`)"
        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata=meta,
            can_list=False,
            can_extract=meta["upx_d_available"],
        )

    def extract(
        self,
        path: Path,
        out_dir: Path,
        detection: Detection,
        *,
        only: Optional[Iterable[str]] = None,
        overwrite: bool = True,
    ) -> list[Path]:
        if not shutil.which("upx"):
            raise UnsupportedOperation(
                "`upx` binary not on PATH; install UPX to unpack."
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        unpacked = out_dir / path.name
        if unpacked.exists() and not overwrite:
            return []
        # `upx -d -o out in` produces the unpacked binary.
        result = subprocess.run(
            ["upx", "-d", "-o", str(unpacked), str(path)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"upx -d failed (rc={result.returncode}): {result.stderr.decode(errors='replace')}"
            )
        return [unpacked]


register_handler(UpxHandler())
