"""Handler for .NET SingleFileBundle apphost binaries.

Recognises ``dotnet publish -p:PublishSingleFile=true`` output and unpacks
the embedded assemblies. Supports header versions 1 (.NET Core 3.x),
2 (.NET 5) and 6 (.NET 6+ with optional DEFLATE compression).

Detection:
    32-byte ``BUNDLE_SIGNATURE`` (SHA-256 of ".net core bundle") is embedded
    at link time. The 8 bytes immediately before it hold the bundle header
    offset patched by the bundler — zero for framework-dependent apphosts.

    The 32-byte ``APP_PATH_PLACEHOLDER`` (SHA-256 of "foobar.exe") proves
    apphost provenance even when no bundle is present.
"""
from __future__ import annotations

import io
import mmap
import os
import re
import struct
import zlib
from pathlib import Path
from typing import BinaryIO, Iterable, Optional

from ..core import Detection, Entry, Handler
from ..pe import pe_machine
from ..registry import register_handler


BUNDLE_SIGNATURE = bytes.fromhex(
    "8b1202b96a612038727b930214d7a032"
    "13f5b9e6efae3318ee3b2dce24b36aae"
)

APP_PATH_PLACEHOLDER = bytes.fromhex(
    "c3ab8ff13720e8ad9047dd39466b3c89"
    "74e592c2fa383d4a3960714caef0c4f2"
)

_D = rb"\d\x00(?:\d\x00)*"
_DOT = rb"\.\x00"
_COMMIT_TAG = rb" \x00@\x00C\x00o\x00m\x00m\x00i\x00t\x00:\x00 \x00"
_HEX40 = rb"(?:[0-9a-f]\x00){40}"
VERSION_BANNER_RE = re.compile(
    b"(" + _D + b")" + _DOT + b"(" + _D + b")" + _DOT + b"(" + _D + b")"
    + _COMMIT_TAG + b"(" + _HEX40 + b")"
)

_FILE_TYPE = {
    0: "Unknown", 1: "Assembly", 2: "NativeBinary",
    3: "DepsJson", 4: "RuntimeConfigJson", 5: "Symbols",
}


def _read_7bit(f: BinaryIO) -> int:
    result, shift = 0, 0
    for _ in range(5):
        b = f.read(1)
        if not b:
            raise EOFError("Unexpected EOF reading 7-bit int")
        v = b[0]
        result |= (v & 0x7F) << shift
        if (v & 0x80) == 0:
            return result
        shift += 7
    raise ValueError("7-bit int wider than 5 bytes")


def _read_lp_string(f: BinaryIO) -> str:
    n = _read_7bit(f)
    return f.read(n).decode("utf-8") if n else ""


def _find_version_banner(view: mmap.mmap) -> tuple[Optional[str], Optional[str]]:
    m = VERSION_BANNER_RE.search(view)
    if not m:
        return None, None
    parts = [m.group(i).decode("utf-16-le") for i in (1, 2, 3)]
    return ".".join(parts), m.group(4).decode("utf-16-le")


class DotNetSingleFileHandler(Handler):
    name = "dotnet-singlefile"
    description = ".NET 3.0+/5/6/7/8/9 SingleFileBundle apphost"

    def detect(self, path: Path) -> Optional[Detection]:
        with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as v:
            sig_pos = v.find(BUNDLE_SIGNATURE)
            has_app_placeholder = v.find(APP_PATH_PLACEHOLDER) != -1
            if sig_pos == -1 and not has_app_placeholder:
                return None

            header_offset = 0
            if sig_pos != -1:
                header_offset = struct.unpack_from("<Q", v, sig_pos - 8)[0]

            arch = pe_machine(v[:0x1000])
            version, commit = _find_version_banner(v)

        is_bundle = header_offset != 0
        meta = {
            "is_bundle": is_bundle,
            "marker_offset": sig_pos if sig_pos >= 0 else None,
            "header_offset": header_offset,
            "dotnet_version": version,
            "dotnet_commit": commit,
            "pe_arch": arch,
        }
        kind = "single-file bundle" if is_bundle else "framework-dependent apphost"
        summary = f".NET {version or '?'} apphost ({arch or '?'}) - {kind}"

        return Detection(
            handler=self.name,
            confidence="high",
            summary=summary,
            metadata=meta,
            can_list=is_bundle,
            can_extract=is_bundle,
        )

    def _parse_manifest(self, path: Path, header_offset: int):
        with path.open("rb") as f:
            f.seek(header_offset)
            major, minor = struct.unpack("<II", f.read(8))
            num_files = struct.unpack("<i", f.read(4))[0]
            if not (0 <= num_files <= 100_000):
                raise ValueError(f"Implausible num_files={num_files}")
            bundle_id = _read_lp_string(f)

            deps_off = deps_sz = rcfg_off = rcfg_sz = 0
            flags = 0
            if major >= 2:
                (deps_off, deps_sz, rcfg_off, rcfg_sz) = struct.unpack("<qqqq", f.read(32))
                flags = struct.unpack("<Q", f.read(8))[0]

            entries = []
            for _ in range(num_files):
                if major >= 6:
                    offset, size, csize = struct.unpack("<qqq", f.read(24))
                else:
                    offset, size = struct.unpack("<qq", f.read(16))
                    csize = 0
                ftype = f.read(1)[0]
                path_rel = _read_lp_string(f)
                entries.append(Entry(
                    name=path_rel,
                    size=size,
                    offset=offset,
                    compressed_size=csize,
                    type=_FILE_TYPE.get(ftype, "Unknown"),
                ))

        header = {
            "header_offset": header_offset,
            "version": (major, minor),
            "bundle_id": bundle_id,
            "deps_json_offset": deps_off,
            "deps_json_size": deps_sz,
            "runtime_config_json_offset": rcfg_off,
            "runtime_config_json_size": rcfg_sz,
            "flags": flags,
        }
        return header, entries

    def list_entries(self, path: Path, detection: Detection) -> list[Entry]:
        ho = detection.metadata.get("header_offset", 0)
        if not ho:
            return []
        header, entries = self._parse_manifest(path, ho)
        detection.metadata["bundle_header"] = header
        return entries

    def extract(
        self,
        path: Path,
        out_dir: Path,
        detection: Detection,
        *,
        only: Optional[Iterable[str]] = None,
        overwrite: bool = True,
    ) -> list[Path]:
        ho = detection.metadata.get("header_offset", 0)
        if not ho:
            raise ValueError("Not a bundle (header_offset=0)")
        _, entries = self._parse_manifest(path, ho)

        out_dir.mkdir(parents=True, exist_ok=True)
        name_set = set(only) if only is not None else None
        written: list[Path] = []

        with path.open("rb") as f:
            for entry in entries:
                if name_set is not None and not (
                    entry.name in name_set
                    or os.path.basename(entry.name) in name_set
                ):
                    continue

                safe = entry.name.replace("\\", "/").lstrip("/")
                if ".." in safe.split("/"):
                    raise ValueError(f"Suspicious entry path: {entry.name!r}")

                out_path = out_dir / safe
                if out_path.exists() and not overwrite:
                    continue
                out_path.parent.mkdir(parents=True, exist_ok=True)

                f.seek(entry.offset)
                data = f.read(entry.compressed_size if entry.is_compressed else entry.size)
                if entry.is_compressed:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)
                    if len(data) != entry.size:
                        raise ValueError(
                            f"{entry.name}: decompressed {len(data)} != expected {entry.size}"
                        )
                out_path.write_bytes(data)
                written.append(out_path)

        return written


register_handler(DotNetSingleFileHandler())
