# unpackr

Detect and unpack Windows packers / wrappers. Extensible via handler plugins.

Given a suspicious `.exe`, `unpackr` tells you what packed it (PyInstaller,
Nuitka, .NET SingleFile, NSIS, Inno Setup, UPX, AutoIt, 7z SFX, MSI, Go,
Costura, Java wrapper, commercial PE protectors, ...) and — where possible —
extracts the embedded payload.

## Install

From a clone:

```
pip install -e .
```

Requires Python 3.9+. No runtime dependencies.

## CLI

The `unpackr` command exposes four subcommands:

| Command                 | What it does                                              |
|-------------------------|-----------------------------------------------------------|
| `unpackr handlers`      | List every registered handler                             |
| `unpackr detect <path>` | Run every handler against a file; show which ones matched |
| `unpackr list <path>`   | Enumerate embedded entries (auto-pick handler)            |
| `unpackr extract <path>`| Unpack embedded entries to a directory                    |

### List available handlers

```
unpackr handlers
```

```
  dotnet-singlefile  .NET 3.0+/5/6/7/8/9 SingleFileBundle apphost
  pyinstaller        PyInstaller frozen executable (CArchive + PYZ)
  upx                UPX-packed PE (detect only; extract via `upx -d`)
  nuitka             Nuitka-compiled Python executable (detect only)
  nsis               Nullsoft NSIS installer (detect only; unpack via 7-Zip)
  go-binary          Go-compiled binary (detect + parse buildinfo)
  innosetup          Inno Setup installer (detect only; unpack via innounp)
  pe-protector       Commercial PE protectors (VMProtect/Themida/Enigma/...)
  autoit             AutoIt-compiled script (detect only; unpack via Exe2Aut)
  7z-sfx             7-Zip self-extracting archive (detect only; unpack via 7z)
  costura            Costura.Fody-embedded .NET assemblies (detect only)
  java-wrapper       Java app wrapped in EXE (install4j/Launch4j/exe4j/JSmooth)
  msi                Windows Installer (MSI) database (detect only; unpack via lessmsi)
```

### Detect

```
unpackr detect suspicious.exe
unpackr detect suspicious.exe -v          # also dump handler metadata
unpackr detect suspicious.exe --json      # machine-readable output
```

Example:

```
File   : suspicious.exe
Size   : 12.4 MB
Matches: 1

  [  high] dotnet-singlefile
           .NET 8.0.10 apphost (x64) - single-file bundle
           capabilities: list, extract
```

Exit code is `0` on match, `1` if nothing recognized the file.

### List embedded entries

```
unpackr list suspicious.exe
unpackr list suspicious.exe --handler pyinstaller   # force a specific handler
unpackr list suspicious.exe --json
```

Example:

```
Handler: dotnet-singlefile  (.NET 8.0.10 apphost (x64) - single-file bundle)
Entries: 142

   #   type             offset         size        csize   name
----------------------------------------------------------------------------------------------------
   0  assembly       0x0000401200      3145728            0   MyApp.dll
   1  assembly       0x0000701200       262144            0   System.Private.CoreLib.dll
   ...
```

### Extract

```
unpackr extract suspicious.exe -o unpacked/
unpackr extract suspicious.exe -o unpacked/ --only MyApp.dll config.json
unpackr extract suspicious.exe -o unpacked/ --handler pyinstaller --no-overwrite -v
```

Flags:

- `-o, --out DIR` — output directory (default: `unpacked`)
- `--handler NAME` — force a specific handler when multiple matched
- `--only NAME ...` — restrict extraction to these entry names
- `--no-overwrite` — skip entries whose target file already exists
- `-v, --verbose` — print every written path

Handlers marked *detect only* in the table above will refuse to extract;
`unpackr` prints the recommended external tool (e.g. `7z`, `innounp`,
`Exe2Aut`, `upx -d`, `lessmsi`).

### Auto-pick rule

If exactly one handler matches, it wins. If several match, the
highest-confidence detection (`high` > `medium` > `low`) is picked.
Pass `--handler NAME` to override.

## Python API

`unpackr` is also a library:

```python
from pathlib import Path
from unpackr import probe, get_handler

# probe() runs every handler against a path, returns matches sorted by confidence.
for handler, detection in probe(Path("suspicious.exe")):
    print(handler.name, detection.confidence, detection.summary)

# Drive a handler directly:
h = get_handler("dotnet-singlefile")
det = h.detect(Path("suspicious.exe"))
if det and det.can_extract:
    h.extract(Path("suspicious.exe"), Path("unpacked"), det)
```

Public types: `Handler`, `Detection`, `Entry`, `UnsupportedOperation`.
Registry helpers: `all_handlers()`, `get_handler(name)`, `probe(path)`,
`register_handler(handler)`.

## Writing a new handler

Subclass `Handler`, set `name` / `description`, implement `detect()`, and
optionally `list_entries()` / `extract()`. Register it at import time.

```python
from pathlib import Path
from typing import Optional
from unpackr import Handler, Detection, register_handler

class MyHandler(Handler):
    name = "my-packer"
    description = "Acme custom packer"

    def detect(self, path: Path) -> Optional[Detection]:
        if path.read_bytes()[:4] != b"ACME":
            return None
        return Detection(
            handler=self.name,
            confidence="high",
            summary="Acme packer v1",
            can_list=False,
            can_extract=False,
        )

register_handler(MyHandler())
```

Drop the module into `src/unpackr/handlers/` and add it to
`_HANDLER_MODULES` in [src/unpackr/handlers/__init__.py](src/unpackr/handlers/__init__.py)
so it loads with the rest.

## Exit codes

- `0` — success (detect: at least one match; list/extract: completed)
- `1` — detect found no matches
- `2` — selected handler can't perform the requested operation
