"""Command-line interface for unpackr.

Subcommands:
    handlers            list every registered handler
    detect <path>       probe all handlers; show which fired
    list <path>         enumerate embedded entries (auto-pick handler)
    extract <path>      unpack entries (auto-pick handler)

Auto-pick: when multiple handlers match, the highest-confidence one wins,
or the user must pass ``--handler NAME``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .core import Detection, Handler, UnsupportedOperation
from .registry import all_handlers, get_handler, probe


def _bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _pick(matches: list[tuple[Handler, Detection]], name: Optional[str]) -> tuple[Handler, Detection]:
    if not matches:
        raise SystemExit("No handler recognized this file. Run `unpackr handlers` to see options.")
    if name:
        for h, d in matches:
            if h.name == name:
                return h, d
        raise SystemExit(f"Handler {name!r} did not match this file.")
    if len(matches) == 1:
        return matches[0]
    # Multiple matched - prefer the highest-confidence one.
    return matches[0]


# ---------------- subcommands ----------------

def cmd_handlers(args: argparse.Namespace) -> int:
    rows = [(h.name, h.description) for h in all_handlers()]
    width = max((len(n) for n, _ in rows), default=4)
    for name, desc in rows:
        print(f"  {name:<{width}}  {desc}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    path = Path(args.path)
    matches = probe(path)
    if args.json:
        payload = [
            {
                "handler": h.name,
                "confidence": d.confidence,
                "summary": d.summary,
                "can_list": d.can_list,
                "can_extract": d.can_extract,
                "metadata": d.metadata,
            }
            for h, d in matches
        ]
        json.dump({"path": str(path), "size": path.stat().st_size, "matches": payload},
                  sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0 if matches else 1

    print(f"File   : {path}")
    print(f"Size   : {_bytes(path.stat().st_size)}")
    if not matches:
        print("Result : no handler matched.")
        return 1
    print(f"Matches: {len(matches)}")
    for h, d in matches:
        print()
        print(f"  [{d.confidence:>6}] {h.name}")
        print(f"           {d.summary}")
        caps = []
        if d.can_list: caps.append("list")
        if d.can_extract: caps.append("extract")
        print(f"           capabilities: {', '.join(caps) or '(detect only)'}")
        if args.verbose:
            for k, v in d.metadata.items():
                print(f"           {k} = {v!r}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    path = Path(args.path)
    matches = probe(path)
    handler, detection = _pick(matches, args.handler)
    if not detection.can_list:
        print(f"{handler.name}: cannot list entries (detect-only).", file=sys.stderr)
        return 2

    try:
        entries = handler.list_entries(path, detection)
    except UnsupportedOperation as e:
        print(str(e), file=sys.stderr)
        return 2

    if args.json:
        json.dump(
            {
                "handler": handler.name,
                "detection": detection.summary,
                "entries": [
                    {"name": e.name, "size": e.size, "offset": e.offset,
                     "compressed_size": e.compressed_size, "type": e.type,
                     "metadata": e.metadata}
                    for e in entries
                ],
            },
            sys.stdout, indent=2, default=str,
        )
        sys.stdout.write("\n")
        return 0

    print(f"Handler: {handler.name}  ({detection.summary})")
    print(f"Entries: {len(entries)}\n")
    if not entries:
        return 0
    print(f"{'#':>4}  {'type':<16} {'offset':>12} {'size':>12} {'csize':>12}  name")
    print("-" * 100)
    for i, e in enumerate(entries):
        print(
            f"{i:>4}  {e.type:<16} "
            f"0x{e.offset:010x} {e.size:>12} {e.compressed_size:>12}  {e.name}"
        )
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    path = Path(args.path)
    matches = probe(path)
    handler, detection = _pick(matches, args.handler)
    if not detection.can_extract:
        print(f"{handler.name}: cannot extract.", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    try:
        written = handler.extract(
            path, out_dir, detection,
            only=args.only or None,
            overwrite=not args.no_overwrite,
        )
    except UnsupportedOperation as e:
        print(str(e), file=sys.stderr)
        return 2

    print(f"[{handler.name}] extracted {len(written)} file(s) -> {out_dir}")
    if args.verbose:
        for p in written:
            print(f"  {p}")
    return 0


# ---------------- argparse ----------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="unpackr",
        description="Detect and unpack Windows packers / wrappers.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    ph = sub.add_parser("handlers", help="list every registered handler")
    ph.set_defaults(func=cmd_handlers)

    pd = sub.add_parser("detect", help="probe a file with all handlers")
    pd.add_argument("path")
    pd.add_argument("--json", action="store_true")
    pd.add_argument("-v", "--verbose", action="store_true", help="show handler metadata")
    pd.set_defaults(func=cmd_detect)

    pl = sub.add_parser("list", help="list embedded entries")
    pl.add_argument("path")
    pl.add_argument("--handler", help="force a specific handler")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_list)

    pe = sub.add_parser("extract", help="unpack embedded entries")
    pe.add_argument("path")
    pe.add_argument("-o", "--out", default="unpacked", help="output directory")
    pe.add_argument("--handler", help="force a specific handler")
    pe.add_argument("--only", nargs="*", help="restrict to these entry names")
    pe.add_argument("--no-overwrite", action="store_true")
    pe.add_argument("-v", "--verbose", action="store_true")
    pe.set_defaults(func=cmd_extract)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
