"""Constructors, `from_bytes` and `to_bytes`, and the binary form of each type."""

import enum
from typing import Any

import pytest
from hypothesis import given

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
    UnsupportedVersionError,
)

from .support import KEY, raises_plain_value_error, strkeys


@given(strkeys)
def test_bytes_round_trip(key: Strkey) -> None:
    assert type(key).from_bytes(key.to_bytes()) == key


@pytest.mark.parametrize("value", [32, None, "x" * 32, bytearray(32), memoryview(KEY)])
def test_non_bytes_key_material_is_a_type_error(value: Any) -> None:
    with pytest.raises(TypeError):
        Ed25519PublicKey(value)
    with pytest.raises(TypeError):
        Ed25519SignedPayload(KEY, value)
    with pytest.raises(TypeError):
        Ed25519SignedPayload.from_bytes(value)
    with pytest.raises(TypeError):
        MuxedContract.from_bytes(value)
    with pytest.raises(TypeError):
        ClaimableBalance.from_bytes(value)


@pytest.mark.parametrize(
    "strkey_type",
    [
        Contract,
        Ed25519PrivateKey,
        Ed25519PublicKey,
        HashX,
        LiquidityPool,
        PreAuthTx,
        ClaimableBalance,
    ],
)
@pytest.mark.parametrize("length", [0, 31, 33])
def test_key_material_must_have_the_right_length(strkey_type: Any, length: int) -> None:
    with raises_plain_value_error():
        strkey_type(bytes(length))


class LyingBytes(bytes):
    """Bytes that misreport their length, their truth value and their content."""

    __slots__ = ()

    def __len__(self) -> int:
        return 32

    def __bool__(self) -> bool:
        return False

    def __bytes__(self) -> bytes:
        return KEY


class HonestBytes(bytes):
    """A bytes subclass that behaves like bytes, as hexbytes.HexBytes does."""

    __slots__ = ()


def test_bytes_subclasses_are_read_for_their_real_content() -> None:
    for strkey_type in (Ed25519PublicKey, Ed25519PrivateKey, Contract):
        with raises_plain_value_error():
            strkey_type(LyingBytes(b"short"))
    with pytest.raises(UnsupportedVersionError):
        ClaimableBalance.from_bytes(LyingBytes(b"\x01" + KEY))


def test_bytes_subclasses_are_stored_as_bytes() -> None:
    key = Ed25519PublicKey(HonestBytes(KEY))
    assert type(key.key) is bytes
    assert key == Ed25519PublicKey(KEY)
    assert hash(key) == hash(Ed25519PublicKey(KEY))
    signed = Ed25519SignedPayload(HonestBytes(KEY), HonestBytes(b"ab"))
    assert type(signed.payload) is bytes
    muxed = MuxedContract.from_bytes(HonestBytes(KEY + bytes(8)))
    assert type(muxed.hash) is bytes
    assert type(Ed25519PrivateKey(HonestBytes(KEY)).seed) is bytes


def test_exact_bytes_are_not_copied() -> None:
    assert Ed25519PublicKey(KEY).key is KEY


def test_fields_hold_the_constructor_arguments() -> None:
    assert Contract(hash=KEY).hash == KEY
    signed = Ed25519SignedPayload(key=KEY, payload=b"ab")
    assert (signed.key, signed.payload) == (KEY, b"ab")
    muxed = MuxedEd25519Account(key=KEY, id=7)
    assert (muxed.key, muxed.id) == (KEY, 7)
    muxed_contract = MuxedContract(hash=KEY, id=7)
    assert (muxed_contract.hash, muxed_contract.id) == (KEY, 7)


@pytest.mark.parametrize("strkey_type", [MuxedEd25519Account, MuxedContract])
def test_muxed_id_is_validated(strkey_type: Any) -> None:
    assert strkey_type(KEY, 2**64 - 1).id == 2**64 - 1
    for out_of_range in (-1, 2**64):
        with raises_plain_value_error():
            strkey_type(KEY, out_of_range)
    for wrong_type in (True, 1.0, "1", None):
        with pytest.raises(TypeError):
            strkey_type(KEY, wrong_type)
    with raises_plain_value_error():
        strkey_type(KEY[:-1], 0)
    with raises_plain_value_error():
        strkey_type.from_bytes(KEY)


class Slot(enum.IntEnum):
    FIRST = 1


@pytest.mark.parametrize("strkey_type", [MuxedEd25519Account, MuxedContract])
def test_int_subclasses_are_stored_as_int(strkey_type: Any) -> None:
    muxed = strkey_type(KEY, Slot.FIRST)
    assert type(muxed.id) is int
    assert muxed == strkey_type(KEY, 1)


def test_muxed_id_is_big_endian() -> None:
    assert MuxedEd25519Account(KEY, 1).to_bytes() == KEY + bytes(7) + b"\x01"
    assert MuxedContract(KEY, 1).to_bytes() == KEY + bytes(7) + b"\x01"


@pytest.mark.parametrize(
    ("length", "valid"),
    [(0, False), (1, True), (4, True), (63, True), (64, True), (65, False)],
)
def test_signed_payload_length_bounds(length: int, *, valid: bool) -> None:
    if valid:
        assert Ed25519SignedPayload(KEY, bytes(length)).payload == bytes(length)
    else:
        with raises_plain_value_error():
            Ed25519SignedPayload(KEY, bytes(length))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "must be 40 to 100 bytes"),
        (KEY + b"\x00\x00\x00", "must be 40 to 100 bytes"),
        (KEY + b"\x00\x00\x00\x00", "must be 40 to 100 bytes"),
        (KEY + b"\xff\xff\xff\xff" + bytes(8), "does not match"),
        (KEY + b"\x00\x00\x00\x01a", "must be 40 to 100 bytes"),
        (KEY + b"\x00\x00\x00\x01a\x00\x00\x00\x00", "does not match"),
        (KEY + b"\x00\x00\x00\x41" + bytes(68), "must be 40 to 100 bytes"),
        (KEY + b"\x00\x00\x00\x01a\x00\x00\x01", "padding"),
        (KEY + b"\x00\x00\x00\x02ab\x00\x00" + bytes(4), "does not match"),
        (KEY + b"\x00\x00\x00\x05abcde\xff", "does not match"),
    ],
)
def test_signed_payload_from_bytes_rejects(data: bytes, message: str) -> None:
    with raises_plain_value_error() as excinfo:
        Ed25519SignedPayload.from_bytes(data)
    assert message in str(excinfo.value)


def test_signed_payload_is_padded_to_four_bytes() -> None:
    key = Ed25519SignedPayload(KEY, b"abcde")
    assert key.to_bytes() == KEY + b"\x00\x00\x00\x05abcde\x00\x00\x00"


def test_claimable_balance_binary_form_starts_with_version() -> None:
    key = ClaimableBalance(KEY)
    assert key.to_bytes() == b"\x00" + KEY
    with pytest.raises(UnsupportedVersionError):
        ClaimableBalance.from_bytes(b"\x01" + KEY)
    with raises_plain_value_error():
        ClaimableBalance.from_bytes(b"")
    with raises_plain_value_error():
        ClaimableBalance.from_bytes(b"\x00" + KEY[:-1])
