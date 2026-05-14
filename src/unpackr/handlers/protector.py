"""Handler for well-known commercial PE protectors (detect only).

Detects VMProtect, Themida/WinLicense, Enigma Protector, ASPack, PECompact,
MPRESS, .NET ConfuserEx — by section names and embedded ASCII strings.
Most of these are anti-RE wrappers that you cannot unpack without dynamic
analysis (Scylla, x64dbg + ScyllaHide, custom unpackers), so this handler
is detect-only and reports *what* it found so the analyst can pick the
right tool.

Heuristic for "looks like VMProtect / random section names": many modern
protectors strip the standard section name list (.text/.rdata/...) and
replace them with random 3-4 byte ASCII. Flagged as low-confidence
"protected-binary" when the standard sections are missing.
"""
from __future__ import annotations

import mmap
import re
import string
from pathlib import Path
from typing import Optional

from ..core import Detection, Handler
from ..pe import pe_section_names
from ..registry import register_handler


# Section-name signatures: any of these in the PE -> we report the protector.
_SECTION_SIGS: dict[str, list[str]] = {
    "VMProtect":      [".vmp0", ".vmp1", ".vmp2"],
    "Themida":        [".themida", ".Themida"],
    "WinLicense":     [".winlice"],
    "Enigma":         [".enigma1", ".enigma2"],
    "ASPack":         [".aspack", "aspack", ".adata"],
    "PECompact":      ["pec", "pec1", "pec2", "PEC2"],
    "MPRESS":         [".MPRESS1", ".MPRESS2"],
    "Petite":         [".petite"],
    "FSG":            [".fsg"],
}

# Byte/string signatures elsewhere in the file (only checked when section
# scan returned nothing useful).
_BYTE_SIGS: dict[str, list[bytes]] = {
    "VMProtect":   [b"VMProtect", b".vmp0\x00", b".vmp1\x00"],
    "Themida":     [b"Themida", b"WinLicense"],
    "Enigma":      [b"Enigma Protector"],
    "ConfuserEx":  [b"ConfusedByAttribute", b"ConfuserEx"],
    "Dotfuscator": [b"DotfuscatorAttribute", b"Dotfuscator"],
    "Eazfuscator": [b"Eazfuscator.NET"],
    "SmartAssembly": [b"PoweredBy", b"SmartAssembly"],
}

_STANDARD_SECTIONS = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".idata",
    ".edata", ".bss", ".tls", ".CRT", ".sdata", ".srdata", ".gfids",
    ".00cfg", ".giats", ".rodata", ".xdata", ".didat", ".debug", ".symtab",
}

_PRINTABLE = set(string.printable.encode())


_WEIRD_CHARS = set("`~!@#$%^&*()+={}[]|\\;:'\",<>?/")


def _looks_random(name: str) -> bool:
    """A section name looks 'random' when it contains punctuation chars not
    found in normal compiler/linker output."""
    if not name or name in _STANDARD_SECTIONS:
        return False
    if name.startswith("/"):
        return False  # COFF long-name pointers like "/4"
    if not all(0x20 <= ord(c) < 0x7F for c in name):
        return True
    # Strip a leading "." prefix used by both real and protector-generated names.
    body = name[1:] if name.startswith(".") else name
    if any(c in _WEIRD_CHARS for c in body):
        return True
    return False


class ProtectorHandler(Handler):
    name = "pe-protector"
    description = "Commercial PE protectors (VMProtect/Themida/Enigma/ConfuserEx/...)"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            sections = pe_section_names(v[:0x2000])
            if not sections:
                return None
            section_set = set(sections)

            section_hits: list[str] = []
            for product, sigs in _SECTION_SIGS.items():
                if section_set.intersection(sigs):
                    section_hits.append(product)

            byte_hits: list[str] = []
            for product, sigs in _BYTE_SIGS.items():
                if any(v.find(s) != -1 for s in sigs):
                    byte_hits.append(product)

            random_sections = [s for s in sections if _looks_random(s)]
            # We treat the binary as obfuscated when several sections look random.
            randomized_sections = len(random_sections) >= 2

        products = sorted(set(section_hits + byte_hits))

        if not products and not randomized_sections:
            return None

        confidence = "high" if products else "medium"
        if randomized_sections and not products:
            # We can see the binary is protected but can't say which product.
            products = ["unknown-protector"]
            confidence = "medium"

        summary = "Protected PE (" + ", ".join(products) + ")"
        hint = _hint_for(products)

        return Detection(
            handler=self.name,
            confidence=confidence,
            summary=summary,
            metadata={
                "products": products,
                "section_hits": section_hits,
                "string_hits": byte_hits,
                "sections": sections,
                "random_sections": random_sections,
                "extraction_hint": hint,
            },
            can_list=False,
            can_extract=False,
        )


def _hint_for(products: list[str]) -> str:
    if "VMProtect" in products:
        return "Dynamic unpack: x64dbg + ScyllaHide; dump + rebuild IAT with Scylla."
    if "Themida" in products or "WinLicense" in products:
        return "Use TitanHide/ScyllaHide; dump at OEP; rebuild imports."
    if "ConfuserEx" in products:
        return "Static deobfuscation: ConfuserEx-Unpacker / de4dot."
    if "Dotfuscator" in products or "Eazfuscator" in products or "SmartAssembly" in products:
        return "Static deobfuscation: de4dot."
    if "ASPack" in products:
        return "Try `aspackdie` or unpack manually (one-step OEP)."
    if "PECompact" in products:
        return "Try `pecompact-unpacker`; or dump at OEP."
    if "MPRESS" in products:
        return "Most modern unpackers handle MPRESS (e.g. PE-Bear)."
    return "Identify the product more precisely before choosing an unpacker."


register_handler(ProtectorHandler())
