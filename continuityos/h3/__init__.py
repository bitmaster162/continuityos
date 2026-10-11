"""H3 R6A pure offline contracts. No host, storage, transport or crypto access.

Importing this package does not register an RPC endpoint or open memory.
Runtime identity and authority verification are explicitly out of scope.
"""

__all__ = ["readonly_contract", "authz_decision"]
