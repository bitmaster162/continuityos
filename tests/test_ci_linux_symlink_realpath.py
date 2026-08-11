"""Linux-only realpath gate that is not allowed to skip on Linux CI."""
import sys

import pytest

from continuityos.gate import ActionSpec, preflight
from continuityos.gate.policy import default_policy


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="mandatory Linux CI contract"
)


def test_linux_symlink_realpath_cannot_bypass_protected_path(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    secret = protected / "secret.txt"
    secret.write_text("local fixture", encoding="utf-8")
    link = tmp_path / "alias"

    # No try/skip: inability to create or resolve this link is a Linux CI failure.
    link.symlink_to(protected, target_is_directory=True)
    linked_secret = link / secret.name
    assert linked_secret.resolve(strict=True) == secret.resolve(strict=True)

    policy = default_policy()
    policy["protected_paths"] = [str(protected / "*")]
    result = preflight(
        ActionSpec(
            tool="file.read",
            command="read",
            paths=[str(linked_secret)],
            cwd=str(tmp_path),
        ),
        policy=policy,
    )
    assert result["decision"] == "REQUIRE_CONFIRMATION"
