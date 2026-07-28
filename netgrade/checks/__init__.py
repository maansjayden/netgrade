"""The seven passive checks.

Each check is one module exposing a ``run`` coroutine with an identical
signature. Nothing in a check module imports another check module: they share
only the contract and the scan context, so any one of them can be read,
tested or replaced on its own.
"""
