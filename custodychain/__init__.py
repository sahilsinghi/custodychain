"""CustodyChain: a tamper-evident chain-of-custody ledger for digital evidence.

* evidence is hashed in fixed chunks into an RFC 9162 Merkle tree
* every analyst action is a signed, hash-chained entry in an append-only log
* the log root is anchored with RFC 3161 timestamps from independent TSAs
* ``custodyverify`` (a separate, standard-library-only package) proves that
  nothing changed between seizure and court
"""

__version__ = "0.1.0"
