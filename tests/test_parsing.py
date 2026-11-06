"""How `parse` and `from_string` pick a type, and the order of their checks."""

# pyright: reportPrivateUsage=false

import pytest
from hypothesis import given

from stellar_strkey import (
    ClaimableBalance,
    Contract,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519SignedPayload,
    MalformedStrkeyError,
    MuxedContract,
    MuxedEd25519Account,
    Strkey,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
    parse,
)
from stellar_strkey._codec import encode

from .support import ALL_TYPES, KEY, SEED, assert_shows_no_other_exception, strkeys


@given(strkeys)
def test_string_round_trip(key: Strkey) -> None:
    assert parse(str(key)) == key
    assert type(key).from_string(str(key)) == key


@given(strkeys)
def test_is_valid_accepts_only_the_exact_type(key: Strkey) -> None:
    for strkey_type in ALL_TYPES:
        assert strkey_type.is_valid(str(key)) == (strkey_type is type(key))


@pytest.mark.parametrize(
    ("parser", "other"),
    [
        (Contract, Ed25519PublicKey(KEY)),
        (Ed25519PublicKey, MuxedEd25519Account(KEY, 1)),
        (Contract, MuxedContract(KEY, 1)),
        (Ed25519PrivateKey, Ed25519SignedPayload(KEY, bytes(64))),
        (MuxedEd25519Account, Ed25519PublicKey(KEY)),
    ],
    ids=lambda value: getattr(value, "__name__", type(value).__name__),
)
def test_from_string_reports_the_wrong_type_whatever_the_length(
    parser: type[Strkey | Ed25519PrivateKey], other: Strkey
) -> None:
    with pytest.raises(WrongStrkeyTypeError) as excinfo:
        parser.from_string(str(other))
    assert excinfo.value.expected is parser
    assert excinfo.value.found is type(other)


def test_from_string_reports_a_private_key_as_the_wrong_type() -> None:
    with pytest.raises(WrongStrkeyTypeError) as excinfo:
        Ed25519PublicKey.from_string(SEED)
    assert excinfo.value.found is Ed25519PrivateKey


@pytest.mark.parametrize("strkey_type", [Contract, Ed25519PrivateKey])
@pytest.mark.parametrize("length", [31, 33, 100])
def test_from_string_reports_a_wrong_length_for_the_right_type(
    strkey_type: type[Contract | Ed25519PrivateKey], length: int
) -> None:
    with pytest.raises(MalformedStrkeyError):
        strkey_type.from_string(encode(strkey_type._VERSION_BYTE, bytes(length)))


@pytest.mark.parametrize("strkey_type", [Contract, Ed25519PrivateKey])
def test_from_string_rejects_more_than_any_type_can_hold(
    strkey_type: type[Contract | Ed25519PrivateKey],
) -> None:
    with pytest.raises(MalformedStrkeyError):
        strkey_type.from_string(encode(strkey_type._VERSION_BYTE, bytes(101)))


@pytest.mark.parametrize(
    ("strkey_type", "payload"),
    [
        (Contract, bytes(33)),
        (Ed25519SignedPayload, KEY + b"\x00\x00\x00\x01a\x00\x00\x01"),
        (MuxedContract, KEY),
    ],
    ids=["contract-too-long", "signed-payload-bad-padding", "muxed-contract-too-short"],
)
def test_invalid_key_material_inside_a_strkey_is_malformed(
    strkey_type: type[Strkey], payload: bytes
) -> None:
    strkey = encode(strkey_type._VERSION_BYTE, payload)
    for parser in (parse, strkey_type.from_string):
        with pytest.raises(MalformedStrkeyError) as excinfo:
            parser(strkey)
        assert_shows_no_other_exception(excinfo.value)


def test_unsupported_claimable_balance_version() -> None:
    strkey = encode(ClaimableBalance._VERSION_BYTE, b"\x01" + KEY)
    with pytest.raises(UnsupportedVersionError):
        parse(strkey)
    with pytest.raises(UnsupportedVersionError):
        ClaimableBalance.from_string(strkey)
