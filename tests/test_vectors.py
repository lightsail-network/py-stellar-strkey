"""Shared strkey test vectors, see ``tests/vectors/strkeys.json``.

The file is language neutral so that other implementations can use it too.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from stellar_strkey import (
    ChecksumMismatchError,
    ClaimableBalance,
    Contract,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519SignedPayload,
    HashX,
    LiquidityPool,
    MalformedStrkeyError,
    MuxedContract,
    MuxedEd25519Account,
    PreAuthTx,
    Strkey,
    StrkeyError,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
    parse,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "strkeys.json").read_text(encoding="utf-8")
)

TYPES: dict[str, type[Strkey | Ed25519PrivateKey]] = {
    "claimable_balance": ClaimableBalance,
    "contract": Contract,
    "ed25519_private_key": Ed25519PrivateKey,
    "ed25519_public_key": Ed25519PublicKey,
    "ed25519_signed_payload": Ed25519SignedPayload,
    "hash_x": HashX,
    "liquidity_pool": LiquidityPool,
    "muxed_contract": MuxedContract,
    "muxed_ed25519_account": MuxedEd25519Account,
    "pre_auth_tx": PreAuthTx,
}

TYPES_BY_PREFIX: dict[str, type[Strkey | Ed25519PrivateKey]] = {
    "B": ClaimableBalance,
    "C": Contract,
    "G": Ed25519PublicKey,
    "L": LiquidityPool,
    "M": MuxedEd25519Account,
    "P": Ed25519SignedPayload,
    "S": Ed25519PrivateKey,
    "T": PreAuthTx,
    "W": MuxedContract,
    "X": HashX,
}

ERRORS: dict[str, type[StrkeyError]] = {
    "checksum_mismatch": ChecksumMismatchError,
    "malformed": MalformedStrkeyError,
    "unsupported_version": UnsupportedVersionError,
}


def expected_value(vector: dict[str, str]) -> Strkey | Ed25519PrivateKey:
    fields = {
        name: value for name, value in vector.items() if name not in {"strkey", "type"}
    }
    # Each type takes different fields, so the arguments are only known at run time.
    arguments: dict[str, Any] = {
        name: int(value) if name == "id" else bytes.fromhex(value)
        for name, value in fields.items()
    }
    return TYPES[vector["type"]](**arguments)


def test_vectors_cover_every_type_and_error() -> None:
    assert {v["type"] for v in VECTORS["valid"]} == set(TYPES)
    assert {v["error"] for v in VECTORS["invalid"]} == set(ERRORS)
    strkeys = [v["strkey"] for v in VECTORS["valid"] + VECTORS["invalid"]]
    assert len(strkeys) == len(set(strkeys))


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["strkey"])
def test_valid_vector_decodes_to_its_fields(vector: dict[str, str]) -> None:
    strkey_type = TYPES[vector["type"]]
    key = strkey_type.from_string(vector["strkey"])
    assert key == expected_value(vector)
    rendered = key.reveal() if isinstance(key, Ed25519PrivateKey) else str(key)
    assert rendered == vector["strkey"]


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["strkey"])
def test_valid_vector_is_parsed_or_refused(vector: dict[str, str]) -> None:
    strkey_type = TYPES[vector["type"]]
    if strkey_type is Ed25519PrivateKey:
        with pytest.raises(WrongStrkeyTypeError) as excinfo:
            parse(vector["strkey"])
        assert excinfo.value.found is Ed25519PrivateKey
    else:
        assert parse(vector["strkey"]) == expected_value(vector)


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["strkey"])
def test_valid_vector_is_the_wrong_type_for_other_parsers(
    vector: dict[str, str],
) -> None:
    strkey_type = TYPES[vector["type"]]
    for other in TYPES.values():
        if other is strkey_type:
            continue
        with pytest.raises(WrongStrkeyTypeError) as excinfo:
            other.from_string(vector["strkey"])
        assert (excinfo.value.expected, excinfo.value.found) == (other, strkey_type)


@pytest.mark.parametrize("vector", VECTORS["invalid"], ids=lambda v: v["strkey"])
def test_invalid_vector_raises_its_error(vector: dict[str, str]) -> None:
    strkey = vector["strkey"]
    expected = ERRORS[vector["error"]]
    generic = Ed25519PrivateKey.from_string if strkey.startswith("S") else parse
    for parser in (generic, TYPES_BY_PREFIX[strkey[0]].from_string):
        with pytest.raises(StrkeyError) as excinfo:
            parser(strkey)
        assert excinfo.type is expected
