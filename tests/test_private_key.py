"""`Ed25519PrivateKey`: redaction, refusal by `parse`, and keeping the seed in."""

# pyright: reportPrivateUsage=false

import copy
import dataclasses
import pickle
import traceback
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from stellar_strkey import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    MalformedStrkeyError,
    StrkeyError,
    WrongStrkeyTypeError,
    parse,
)
from stellar_strkey._codec import encode

from .support import KEY, SEED


def test_round_trip() -> None:
    key = Ed25519PrivateKey.from_string(SEED)
    assert key.reveal() == SEED
    assert Ed25519PrivateKey.from_bytes(key.to_bytes()) == key
    assert Ed25519PrivateKey.is_valid(SEED)


def test_is_never_rendered_implicitly() -> None:
    key = Ed25519PrivateKey.from_string(SEED)
    rendered_forms = (
        str(key),
        repr(key),
        f"{key}",
        f"{key!r}",
        f"{key:>80}",
        "%s" % key,  # noqa: UP031
    )
    for rendered in rendered_forms:
        assert SEED not in rendered
        assert key.seed.hex() not in rendered
        assert "redacted" in rendered


def test_parse_refuses_private_keys() -> None:
    with pytest.raises(WrongStrkeyTypeError) as excinfo:
        parse(SEED)
    assert excinfo.value.expected is None
    assert excinfo.value.found is Ed25519PrivateKey
    assert str(excinfo.value) == (
        "parse() does not return private keys; use Ed25519PrivateKey.from_string"
    )


def test_parse_refuses_private_keys_before_checking_their_length() -> None:
    # Like a typed parser given another type, parse() checks only the version byte.
    strkey = encode(Ed25519PrivateKey._VERSION_BYTE, bytes(33))
    with pytest.raises(WrongStrkeyTypeError):
        parse(strkey)
    with pytest.raises(MalformedStrkeyError):
        Ed25519PrivateKey.from_string(strkey)


@pytest.mark.parametrize(
    "broken",
    [SEED[:-1] + "A", SEED[:-1], SEED.lower(), SEED + "A", "é" + SEED],
)
def test_errors_do_not_contain_the_input(broken: str) -> None:
    with pytest.raises(StrkeyError) as excinfo:
        Ed25519PrivateKey.from_string(broken)
    rendered = "".join(traceback.format_exception(excinfo.value))
    assert broken[1:20] not in rendered
    assert repr(broken) not in repr(excinfo.value)


def test_equality_without_hash() -> None:
    key = Ed25519PrivateKey(KEY)
    assert key == Ed25519PrivateKey(KEY)
    assert key != Ed25519PrivateKey(bytes(32))
    public_key: object = Ed25519PublicKey(KEY)
    assert key != public_key
    with pytest.raises(TypeError):
        hash(key)


def test_is_immutable() -> None:
    key = Ed25519PrivateKey(KEY)
    with pytest.raises(FrozenInstanceError):
        key.seed = bytes(32)  # type: ignore[misc]  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(FrozenInstanceError):
        key._seed = bytes(32)
    with pytest.raises(FrozenInstanceError):
        key.other = 1
    with pytest.raises(FrozenInstanceError):
        del key.seed  # pyright: ignore[reportAttributeAccessIssue]
    assert not hasattr(key, "__dict__")
    assert key.seed == KEY


def test_structural_pattern_matching() -> None:
    match Ed25519PrivateKey(KEY):
        case Ed25519PrivateKey(seed):
            assert seed == KEY


def test_is_not_a_dataclass() -> None:
    key: Any = Ed25519PrivateKey(KEY)
    assert not dataclasses.is_dataclass(key)
    with pytest.raises(TypeError):
        dataclasses.asdict(key)


def test_stays_redacted_inside_your_own_dataclass() -> None:
    @dataclasses.dataclass
    class Wallet:
        name: str
        key: Ed25519PrivateKey

    key = Ed25519PrivateKey(KEY)
    dumped = dataclasses.asdict(Wallet("main", key))
    assert dumped["key"] is key
    assert KEY.hex() not in str(dumped)
    assert repr(KEY)[2:-1] not in str(dumped)


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_cannot_be_pickled(protocol: int) -> None:
    with pytest.raises(TypeError, match=r"use reveal\(\)") as excinfo:
        pickle.dumps(Ed25519PrivateKey(KEY), protocol=protocol)
    assert KEY.hex() not in str(excinfo.value)


def test_state_is_not_exposed() -> None:
    with pytest.raises(TypeError, match=r"use reveal\(\)"):
        Ed25519PrivateKey(KEY).__getstate__()


def test_copy_returns_the_same_key() -> None:
    key = Ed25519PrivateKey(KEY)
    assert copy.copy(key) is key
    assert copy.deepcopy(key) is key
    assert copy.deepcopy({"keys": [key]})["keys"][0] is key
