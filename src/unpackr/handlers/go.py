"""Handler for Go binaries (detect + parse buildinfo).

Every Go-compiled binary (since Go 1.12) embeds a ``buildinfo`` blob marked
by the 14-byte magic ``\\xff Go buildinf:``. Layout::

    magic[14]      = "\\xff Go buildinf:"
    ptrSize        : uint8   (4 or 8)
    flags          : uint8   bit 1 = endian (0 = LE, 1 = BE)
                             bit 2 = "varint mode" (Go 1.18+)
    rest           : varies — either pointers to strings (older) or
                     varint-prefixed inline strings (Go 1.18+).

We pull out the Go runtime version (e.g. ``"go1.22.3"``) and, when present,
the main module path. This is detect-only — there is nothing to "unpack".

Reference: ``runtime/debug.ReadBuildInfo``, src/debug/buildinfo/buildinfo.go.
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


GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
# Fallback: "go1.X.Y" version string is always embedded
_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?(?:[a-z0-9.-]*)?")


def _read_varint_string(view, off: int) -> tuple[Optional[str], int]:
    n = 0
    shift = 0
    cur = off
    done = False
    while cur < len(view) and shift < 35:
        b = view[cur]
        cur += 1
        n |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            done = True
            break
        shift += 7
    if not done:
        return None, off
    if n == 0 or cur + n > len(view) or n > 4096:
        return None, off
    try:
        return bytes(view[cur:cur + n]).decode("utf-8"), cur + n
    except UnicodeDecodeError:
        return None, off


class GoBinaryHandler(Handler):
    name = "go-binary"
    description = "Go-compiled binary (detect + parse buildinfo)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            pos = v.find(GO_BUILDINFO_MAGIC)
            arch = pe_machine(v[:0x1000])

            if pos == -1:
                # Fallback: just a Go version string. Lower confidence.
                m = _GO_VERSION_RE.search(v)
                if not m:
                    return None
                return Detection(
                    handler=self.name,
                    confidence="medium",
                    summary=f"Go binary ({m.group(0).decode()}) — buildinfo magic missing",
                    metadata={
                        "version": m.group(0).decode(),
                        "buildinfo_offset": None,
                        "pe_arch": arch,
                    },
                    can_list=False,
                    can_extract=False,
                )

            ptr_size = v[pos + 14]
            flags = v[pos + 15]
            big_endian = bool(flags & 0x01)
            varint_mode = bool(flags & 0x02)

            version = None
            module = None

            if varint_mode:
                ver, nxt = _read_varint_string(v, pos + 32)
                if ver:
                    version = ver
                    mod, _ = _read_varint_string(v, nxt)
                    module = mod
            else:
                # Older format: 2 pointers (ptr_size each) to version, module
                end = "<" if not big_endian else ">"
                fmt = end + ("I" if ptr_size == 4 else "Q")
                try:
                    ver_ptr = struct.unpack_from(fmt, v, pos + 16)[0]
                    mod_ptr = struct.unpack_from(fmt, v, pos + 16 + ptr_size)[0]
                    # Pointers are VAs — we can't easily resolve without
                    # parsing the PE. Fall back to regex.
                except struct.error:
                    pass

            if not version:
                m = _GO_VERSION_RE.search(v)
                if m:
                    version = m.group(0).decode()

        return Detection(
            handler=self.name,
            confidence="high",
            summary=f"Go binary ({version or 'unknown version'})",
            metadata={
                "version": version,
                "module": module,
                "buildinfo_offset": pos,
                "ptr_size": ptr_size,
                "big_endian": big_endian,
                "varint_mode": varint_mode,
                "pe_arch": arch,
            },
            can_list=False,
            can_extract=False,
        )


register_handler(GoBinaryHandler())
