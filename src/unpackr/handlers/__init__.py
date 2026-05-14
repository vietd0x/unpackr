"""Importing this package registers all bundled handlers.

Adding a new handler: drop a module here that calls
``register_handler(MyHandler())`` at import time, then add it to the
``_HANDLER_MODULES`` list below.
"""
from importlib import import_module

_HANDLER_MODULES = [
    "unpackr.handlers.dotnet_singlefile",
    "unpackr.handlers.pyinstaller",
    "unpackr.handlers.upx",
    "unpackr.handlers.nuitka",
    "unpackr.handlers.nsis",
    "unpackr.handlers.go",
    "unpackr.handlers.innosetup",
    "unpackr.handlers.protector",
    "unpackr.handlers.autoit",
    "unpackr.handlers.sfx7z",
    "unpackr.handlers.costura",
    "unpackr.handlers.java_wrapper",
    "unpackr.handlers.msi",
]

for _name in _HANDLER_MODULES:
    import_module(_name)

del import_module, _name
