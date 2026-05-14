"""Handler registry.

Handlers register themselves at import time. :func:`probe` runs every
registered handler against a file and returns all that fired, ranked by
confidence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .core import Detection, Handler


_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

_HANDLERS: list[Handler] = []


def register_handler(handler: Handler) -> Handler:
    """Add *handler* to the global registry. Returns the handler unchanged."""
    if not handler.name:
        raise ValueError(f"Handler {handler!r} has empty .name")
    if any(h.name == handler.name for h in _HANDLERS):
        raise ValueError(f"Handler {handler.name!r} already registered")
    _HANDLERS.append(handler)
    return handler


def all_handlers() -> list[Handler]:
    """All registered handlers, in registration order."""
    return list(_HANDLERS)


def get_handler(name: str) -> Optional[Handler]:
    for h in _HANDLERS:
        if h.name == name:
            return h
    return None


def probe(path: str | Path) -> list[tuple[Handler, Detection]]:
    """Run every handler against *path*. Returns matches sorted by confidence."""
    p = Path(path)
    hits: list[tuple[Handler, Detection]] = []
    for h in _HANDLERS:
        try:
            d = h.detect(p)
        except Exception:
            # A misbehaving handler should not block others.
            continue
        if d is not None:
            hits.append((h, d))
    hits.sort(key=lambda hd: _CONFIDENCE_RANK.get(hd[1].confidence, 99))
    return hits
