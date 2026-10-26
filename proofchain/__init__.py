"""ProofChain: local Merkle proofs for document integrity."""

from .registry import Registry
from .verifier import canonicalize, check_anchor_chain, verify

__all__ = ["Registry", "canonicalize", "check_anchor_chain", "verify"]
__version__ = "1.0.0"
