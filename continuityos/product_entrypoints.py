"""Product entrypoint additions layered over the existing fail-closed cos router."""
from __future__ import annotations

from typing import Sequence

from . import current_entrypoints as _current


def _demo_args(args: Sequence[str]) -> list[str]:
    # Reuse the existing product-argument framing.  A top-level --db is preserved
    # intentionally so continuityos.demo can reject it explicitly: the demo must
    # never touch a user's selected memory database.
    return _current._product_args(args, "demo")


def cos_main(argv: Sequence[str] | None = None) -> int:
    args = _current._args(argv)
    command = _current._command("cos", args)
    if command != "demo":
        return _current.cos_main(args)

    def load():
        from .demo import main as demo_main

        def routed(passed: Sequence[str] | None = None) -> int:
            return int(demo_main(_demo_args(_current._args(passed))) or 0)

        return routed

    # Critical: demo writes an ephemeral DB and starts one local child process.
    # It must therefore remain behind the exact same current-session containment
    # as every other packaged product surface.  A verified R64 READ_ONLY session
    # will HOLD here before demo.py is imported or any temporary file is created.
    return _current._dispatch("cos", args, load)
