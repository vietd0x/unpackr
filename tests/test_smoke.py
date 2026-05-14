"""Smoke tests against artifacts in this repo."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unpackr import probe, get_handler, all_handlers
from unpackr.core import Detection

REPO = Path(__file__).resolve().parents[2]
DOTNET_TARGET = REPO / "RemoteAgentInstaller.exe"


def test_handlers_registered():
    names = {h.name for h in all_handlers()}
    expected = {
        "dotnet-singlefile", "pyinstaller", "upx",
        "nuitka", "nsis", "go-binary", "innosetup", "pe-protector",
    }
    assert expected.issubset(names), expected - names


def test_each_handler_runs_without_throwing():
    """Catches bugs like the memoryview/mmap one — probe() would silence them."""
    for h in all_handlers():
        h.detect(DOTNET_TARGET)
        np = Path(r"C:\Windows\notepad.exe")
        if np.exists():
            h.detect(np)


def test_dotnet_detect():
    matches = probe(DOTNET_TARGET)
    by_name = {h.name: d for h, d in matches}
    assert "dotnet-singlefile" in by_name
    d = by_name["dotnet-singlefile"]
    assert d.confidence == "high"
    assert d.metadata["is_bundle"]
    assert d.metadata["dotnet_version"] == "8.0.8"
    assert d.metadata["pe_arch"] == "x86"
    assert d.metadata["header_offset"] == 0x08AA289F
    assert d.can_list and d.can_extract


def test_dotnet_list_entries():
    h = get_handler("dotnet-singlefile")
    matches = probe(DOTNET_TARGET)
    d = next(det for hh, det in matches if hh.name == "dotnet-singlefile")
    entries = h.list_entries(DOTNET_TARGET, d)
    assert len(entries) == 446
    main_dll = next(e for e in entries if e.name == "RemoteAgentInstaller.dll")
    assert main_dll.type == "Assembly"
    assert main_dll.size == 95744


def test_notepad_no_match():
    notepad = Path(r"C:\Windows\notepad.exe")
    if notepad.exists():
        matches = probe(notepad)
        names = {h.name for h, _ in matches}
        # notepad is not packed by anything we know
        assert "dotnet-singlefile" not in names
        assert "pyinstaller" not in names


if __name__ == "__main__":
    test_handlers_registered()
    test_dotnet_detect()
    test_dotnet_list_entries()
    test_notepad_no_match()
    print("OK")
