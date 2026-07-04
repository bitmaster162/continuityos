"""Deprecated alias — renamed to `continuityos.bus` to avoid confusion with the
Linux Foundation **A2A** protocol. Import from continuityos.bus instead.
`cos a2a ...` still works as an alias for `cos bus ...`."""
from __future__ import annotations
from .bus import (READ_METHODS, WRITE_METHODS, SCOPE_METHODS, mint_token,  # noqa: F401
                  verify_token, build_dispatch, make_handler, serve)
