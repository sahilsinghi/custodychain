"""custodyverify: an independent, read-only verifier for CustodyChain cases.

Design rule: this package imports nothing from ``custodychain`` and nothing
outside the Python standard library. The ASN.1/DER parser, Merkle-tree
maths, canonical-JSON check, Ed25519, RSA and ECDSA signature verification
and the X.509 / RFC 3161 checks are all written separately from the writer,
so a bug in the writer cannot hide in the verifier, and the verifier can be
audited (or rewritten in another language) on its own.
"""

__version__ = "0.1.0"
