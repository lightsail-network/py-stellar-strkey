"""The strkey format: base32, length, checksum and version byte, and hostile input."""

# pyright: reportPrivateUsage=false

from typing import Any

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from stellar_strkey import (
    ChecksumMismatchError,
    Contract,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    HashX,
    LiquidityPool,
    MalformedStrkeyError,
    PreAuthTx,
    Strkey,
    StrkeyError,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
    parse,
)
from stellar_strkey._codec import encode

from .support import ALL_TYPES, ALPHABET, KEY, assert_shows_no_other_exception, strkeys


@given(strkeys)
def test_prefix_matches_version_byte(key: Strkey) -> None:
    assert ord(str(key)[0]) - ord("A") == key._VERSION_BYTE >> 3


@given(st.text())
@example("")
@example("=" * 8)
@example("é" * 56)
@example("G" + "\n" * 55)
def test_arbitrary_text_is_only_ever_rejected_with_strkey_error(value: str) -> None:
    try:
        parse(value)
    except StrkeyError:
        return
    # Random text would need canonical base32, a known version byte and a matching
    # checksum to be valid, which is too unlikely to ever happen by chance.
    pytest.fail("parse() accepted arbitrary text")


@given(strkeys.filter(lambda key: len(str(key)) % 8 != 0))
def test_unused_trailing_bits_must_be_zero(key: Strkey) -> None:
    # These bits are outside the decoded bytes, so the checksum still matches and only
    # the canonical encoding check can catch them.
    strkey = str(key)
    mutated = strkey[:-1] + ALPHABET[ALPHABET.index(strkey[-1]) + 1]
    with pytest.raises(MalformedStrkeyError):
        parse(mutated)


@given(strkeys, st.integers(min_value=0), st.sampled_from(ALPHABET))
def test_any_single_character_change_is_rejected(
    key: Strkey, position: int, replacement: str
) -> None:
    strkey = str(key)
    position %= len(strkey)
    mutated = strkey[:position] + replacement + strkey[position + 1 :]
    if mutated == strkey:
        return
    # CRC16 detects any error of a single 5-bit symbol. The version byte changing to
    # another valid type is also covered, because the checksum spans the version byte.
    with pytest.raises(StrkeyError):
        parse(mutated)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "AAAA",
        "A",
        "A" * 3,
        "A" * 6,
        "G" * 168,
        "é" * 56,
        "g" * 56,
        "1" * 56,
        "A" * 40 + "=" * 16,
        "Snot even a strkey",
    ],
)
def test_malformed_input(value: str) -> None:
    with pytest.raises(MalformedStrkeyError) as excinfo:
        parse(value)
    assert excinfo.type is MalformedStrkeyError
    assert_shows_no_other_exception(excinfo.value)


def test_checksum_mismatch_is_malformed() -> None:
    with pytest.raises(ChecksumMismatchError) as excinfo:
        parse("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGA")
    assert isinstance(excinfo.value, MalformedStrkeyError)


@pytest.mark.parametrize("version", range(256))
def test_only_known_version_bytes_are_accepted(version: int) -> None:
    known = {strkey_type._VERSION_BYTE: strkey_type for strkey_type in ALL_TYPES}
    strkey = encode(version, bytes(32))
    if version == Ed25519PrivateKey._VERSION_BYTE:
        with pytest.raises(WrongStrkeyTypeError):
            parse(strkey)
    elif version in {
        Ed25519PublicKey._VERSION_BYTE,
        PreAuthTx._VERSION_BYTE,
        HashX._VERSION_BYTE,
        Contract._VERSION_BYTE,
        LiquidityPool._VERSION_BYTE,
    }:
        assert isinstance(parse(strkey), known[version])
    elif version in known:
        with pytest.raises(MalformedStrkeyError):
            parse(strkey)
    else:
        with pytest.raises(UnsupportedVersionError):
            parse(strkey)


@pytest.mark.parametrize("strkey_type", [Ed25519PublicKey, Ed25519PrivateKey])
def test_nonzero_algorithm_bits_are_unsupported(
    strkey_type: type[Ed25519PublicKey | Ed25519PrivateKey],
) -> None:
    with pytest.raises(UnsupportedVersionError):
        strkey_type.from_string(encode(strkey_type._VERSION_BYTE | 0b111, bytes(32)))


@pytest.mark.parametrize("value", [None, 1, b"GABC", ["G"]])
def test_non_string_input_is_a_type_error(value: Any) -> None:
    with pytest.raises(TypeError):
        parse(value)
    with pytest.raises(TypeError):
        Contract.from_string(value)
    assert not Contract.is_valid(value)


class Address(str):
    """A str subclass that behaves like str."""

    __slots__ = ()


def test_str_subclasses_are_accepted() -> None:
    contract = Address(str(Contract(KEY)))
    assert parse(contract) == Contract(KEY)
    assert Contract.from_string(contract) == Contract(KEY)
    assert Contract.is_valid(contract)
