"""Core types shared by all handlers.

A *handler* is a small plugin that knows one packer / wrapper format. It
detects the format, lists its embedded entries, and (optionally) extracts
them. New handlers only need to subclass :class:`Handler`, populate the
class attributes, and call :func:`register_handler`.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


Confidence = str  # "high" | "medium" | "low"


@dataclass
class Detection:
    """Returned by :meth:`Handler.detect` when a handler recognizes a file."""

    handler: str
    confidence: Confidence
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    can_list: bool = False
    can_extract: bool = False


@dataclass
class Entry:
    """One logical item embedded in a packed file."""

    name: str                              # relative path / logical name
    size: int                              # uncompressed size
    offset: int = 0                        # raw byte offset (handler-defined)
    compressed_size: int = 0               # 0 = stored / uncompressed
    type: str = ""                         # handler-specific category
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_compressed(self) -> bool:
        return self.compressed_size != 0


class UnsupportedOperation(Exception):
    """Raised when a handler is asked to do something it does not support."""


class Handler(abc.ABC):
    """Base class for all packer handlers."""

    #: stable short id (e.g. ``"dotnet-singlefile"``); shown in CLI
    name: str = ""
    #: one-line human description shown by ``unpackr handlers``
    description: str = ""

    @abc.abstractmethod
    def detect(self, path: Path) -> Optional[Detection]:
        """Probe *path*. Return :class:`Detection` on match, else ``None``."""

    def list_entries(self, path: Path, detection: Detection) -> list[Entry]:
        """Enumerate embedded entries. Override if ``can_list = True``."""
        raise UnsupportedOperation(
            f"{self.name} does not support listing entries"
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
        """Materialize entries to *out_dir*. Override if ``can_extract = True``."""
        raise UnsupportedOperation(
            f"{self.name} does not support extraction"
        )
