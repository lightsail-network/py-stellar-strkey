"""Constants, Hypothesis strategies and assertions shared by the tests."""

from typing import Any

import pytest
from hypothesis import strategies as st

from stellar_strkey import (
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
    StrkeyError,
)

KEY = bytes(range(32))
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
SEED = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR"

keys32 = st.binary(min_size=32, max_size=32)
ids = st.integers(min_value=0, max_value=2**64 - 1)
inner_payloads = st.binary(min_size=1, max_size=64)

strkeys: st.SearchStrategy[Strkey] = st.one_of(
    keys32.map(Ed25519PublicKey),
    st.builds(MuxedEd25519Account, keys32, ids),
    st.builds(Ed25519SignedPayload, keys32, inner_payloads),
    keys32.map(PreAuthTx),
    keys32.map(HashX),
    keys32.map(Contract),
    keys32.map(LiquidityPool),
    keys32.map(ClaimableBalance),
    st.builds(MuxedContract, keys32, ids),
)
"""Any valid strkey that `parse` returns, which excludes private keys."""

ALL_TYPES: list[type[Strkey | Ed25519PrivateKey]] = [
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
]


def raises_plain_value_error() -> Any:
    """Expect a ValueError that is not a StrkeyError, as constructors raise."""
    return pytest.raises(ValueError, check=lambda e: not isinstance(e, StrkeyError))


def assert_shows_no_other_exception(error: BaseException) -> None:
    """Check that a traceback of the error shows no exception it replaced."""
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__
