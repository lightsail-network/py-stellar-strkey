"""Encode and decode Stellar strkeys as defined by SEP-23.

Every strkey type has its own immutable class. Use `parse` when the type is not known
in advance. See https://stellar-strkey.readthedocs.io/ for the guide.
"""

from ._errors import (
    ChecksumMismatchError,
    MalformedStrkeyError,
    StrkeyError,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
)
from ._keys import (
    ClaimableBalance,
    Contract,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519SignedPayload,
    HashX,
    LiquidityPool,
    MuxedContract,
    MuxedEd25519Account,
    PreAuthTx,
    Strkey,
    parse,
)

__all__ = [
    "ChecksumMismatchError",
    "ClaimableBalance",
    "Contract",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "Ed25519SignedPayload",
    "HashX",
    "LiquidityPool",
    "MalformedStrkeyError",
    "MuxedContract",
    "MuxedEd25519Account",
    "PreAuthTx",
    "Strkey",
    "StrkeyError",
    "UnsupportedVersionError",
    "WrongStrkeyTypeError",
    "parse",
]

# Show the public path in tracebacks and pickles, so that old pickles stay loadable when
# the private modules are reorganized. A union alias has no `__module__` to set.
#
# The cost is that inspect.getsource() can't find the classes, so tools that read the
# source at run time, such as IPython's `??` and Sphinx's viewcode, can't show it. IDEs
# and mkdocstrings read the files directly and are not affected.
for _name in __all__:
    if _name != "Strkey":
        globals()[_name].__module__ = __name__
del _name  # pyright: ignore[reportPossiblyUnboundVariable]
