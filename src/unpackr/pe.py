"""Tiny PE header reader shared by handlers (no external deps)."""
from __future__ import annotations

import struct
from typing import Optional


_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01C4: "arm"}


def pe_machine(view: bytes | memoryview) -> Optional[str]:
    """Return ``"x86"`` / ``"x64"`` / ``"arm64"`` or ``None`` if not a PE."""
    if len(view) < 0x40 or bytes(view[:2]) != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", view, 0x3C)[0]
    if e_lfanew + 6 > len(view) or bytes(view[e_lfanew:e_lfanew + 4]) != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", view, e_lfanew + 4)[0]
    return _MACHINE.get(machine, f"0x{machine:04x}")


def pe_section_names(view: bytes | memoryview) -> list[str]:
    """Return the list of PE section names, or ``[]`` if not a PE."""
    if len(view) < 0x40 or bytes(view[:2]) != b"MZ":
        return []
    e_lfanew = struct.unpack_from("<I", view, 0x3C)[0]
    if bytes(view[e_lfanew:e_lfanew + 4]) != b"PE\x00\x00":
        return []
    num_sections = struct.unpack_from("<H", view, e_lfanew + 6)[0]
    size_of_optional = struct.unpack_from("<H", view, e_lfanew + 20)[0]
    sect_table = e_lfanew + 24 + size_of_optional
    out = []
    for i in range(num_sections):
        name = bytes(view[sect_table + i * 40:sect_table + i * 40 + 8])
        out.append(name.rstrip(b"\x00").decode("ascii", errors="replace"))
    return out
