# MCP owner-forget guard R3 (draft)

The legacy MCP server denies forget by default at the Server.call dispatch boundary and hides it from the default tools/list catalog. This is independent of the R6.1 status-only adapter.

Explicit owner mode is opt-in only: the operator must launch the MCP stdio process with --enable-owner-forget and separately supply CONTINUITYOS_OWNER_FORGET_SHA256 (64 lowercase hexadecimal digits) in the process environment. No actual key is generated, read, changed or committed by this PR. An enabled forget call also requires a per-call owner_capability string (32..256 characters); its SHA-256 is checked with constant-time hmac.compare_digest against the configured digest. Id must be a positive integer and no extra arguments are accepted. Missing, malformed or mismatched credentials are rejected before memory deletion.

A raw hash of a weak secret is not secure: any future production admission must use high-entropy, privately provisioned owner capability, protected local process configuration, explicit human approval, and independent revocation/rotation review. Stdio client access must not be assumed to prove owner identity. No existing client should be wired through this experimental path.

Tests use only fake memory and synthetic capabilities. Run python -m pytest -q tests/test_mcp_owner_forget_guard_r3.py. This draft does not enable forget anywhere in live runtime.

STOP: No merge, deployment, server changes, key changes or client connections.
