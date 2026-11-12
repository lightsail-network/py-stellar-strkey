"""Behaviour as Python objects, the error classes and the public API."""

import copy
import dataclasses
import pickle
import traceback

import pytest
from hypothesis import given

import stellar_strkey
from stellar_strkey import (
    ChecksumMismatchError,
    Contract,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    LiquidityPool,
    MalformedStrkeyError,
    MuxedEd25519Account,
    Strkey,
    StrkeyError,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
    parse,
)

from .support import KEY, raises_plain_value_error, strkeys


def test_keys_are_immutable_and_slotted() -> None:
    key = Ed25519PublicKey(KEY)
    with pytest.raises(AttributeError):
        key.key = bytes(32)  # type: ignore[misc]  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError):
        key._key = bytes(32)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(AttributeError):
        del key.key  # pyright: ignore[reportAttributeAccessIssue]
    contract = Contract(KEY)
    assert not hasattr(key, "__dict__")
    assert not hasattr(contract, "__dict__")
    with pytest.raises(AttributeError):
        contract.other = 1
    assert key.key == KEY


def test_equality_and_hash_depend_on_type_and_value() -> None:
    assert Contract(KEY) == Contract(KEY)
    assert hash(Contract(KEY)) == hash(Contract(KEY))
    assert Contract(KEY) != Contract(bytes(32))
    other_types: list[object] = [LiquidityPool(KEY), Ed25519PublicKey(KEY)]
    assert all(Contract(KEY) != other for other in other_types)
    assert all(hash(Contract(KEY)) != hash(other) for other in other_types)
    assert len({Contract(KEY), Contract(KEY), LiquidityPool(KEY)}) == 2


@given(strkeys)
def test_isinstance_of_the_strkey_union(key: Strkey) -> None:
    assert isinstance(key, Strkey)
    assert not isinstance(Ed25519PrivateKey(KEY), Strkey)


@dataclasses.dataclass
class Holder:
    key: Strkey


@given(strkeys)
def test_strkeys_are_not_records_to_take_apart(key: Strkey) -> None:
    assert not dataclasses.is_dataclass(key)
    assert dataclasses.asdict(Holder(key)) == {"key": key}


@given(strkeys)
def test_pickle_and_copy_preserve_public_keys(key: Strkey) -> None:
    assert pickle.loads(pickle.dumps(key)) == key
    assert copy.copy(key) is key
    assert copy.deepcopy(key) is key


class ForgedPickle:
    """Pickles as a contract whose binary form is too short."""

    def __reduce__(self) -> tuple[object, tuple[bytes]]:
        return Contract.from_bytes, (b"short",)


def test_a_pickle_holds_the_binary_form_and_is_validated_when_loaded() -> None:
    key = MuxedEd25519Account(KEY, 7)
    assert key.__reduce__() == (MuxedEd25519Account.from_bytes, (key.to_bytes(),))
    with raises_plain_value_error():
        pickle.loads(pickle.dumps(ForgedPickle()))


def test_repr_shows_the_strkey() -> None:
    key = Contract(KEY)
    assert repr(key) == f"Contract.from_string({str(key)!r})"


@given(strkeys)
def test_repr_evaluates_to_an_equal_key(key: Strkey) -> None:
    assert eval(repr(key), dict(vars(stellar_strkey))) == key  # noqa: S307


@pytest.mark.parametrize("spec", ["", "s", ">80", "^80", "<80"])
def test_format_behaves_like_the_strkey_string(spec: str) -> None:
    key = Contract(KEY)
    assert format(key, spec) == format(str(key), spec)


def test_structural_pattern_matching() -> None:
    match parse(str(MuxedEd25519Account(KEY, 7))):
        case MuxedEd25519Account(key, id):
            assert (key, id) == (KEY, 7)
        case _:  # pragma: no cover
            pytest.fail("did not match")


def test_wrong_type_error_is_picklable_and_readable() -> None:
    error = WrongStrkeyTypeError(Contract, Ed25519PublicKey)
    restored = pickle.loads(pickle.dumps(error))
    assert (restored.expected, restored.found) == (Contract, Ed25519PublicKey)
    assert str(restored) == str(error)
    assert str(error) == (
        "expected a strkey of type Contract, got one of type Ed25519PublicKey"
    )
    restored_none = pickle.loads(pickle.dumps(WrongStrkeyTypeError(None, Contract)))
    assert restored_none.expected is None


def test_error_hierarchy() -> None:
    assert issubclass(StrkeyError, ValueError)
    for error in (MalformedStrkeyError, UnsupportedVersionError, WrongStrkeyTypeError):
        assert issubclass(error, StrkeyError)
    assert issubclass(ChecksumMismatchError, MalformedStrkeyError)


def test_public_api_is_sorted_and_importable() -> None:
    names = stellar_strkey.__all__
    assert names == sorted(names)
    assert all(hasattr(stellar_strkey, name) for name in names)
    assert not hasattr(stellar_strkey, "_name")


@pytest.mark.parametrize("name", sorted(set(stellar_strkey.__all__) - {"Strkey"}))
def test_public_objects_report_the_public_module(name: str) -> None:
    assert getattr(stellar_strkey, name).__module__ == "stellar_strkey"


def test_pickles_reference_the_public_module_only() -> None:
    for value in (Contract(KEY), WrongStrkeyTypeError(Contract, Ed25519PublicKey)):
        pickled = pickle.dumps(value)
        assert b"stellar_strkey" in pickled
        assert b"_keys" not in pickled
        assert b"_errors" not in pickled


def test_errors_render_with_the_public_module() -> None:
    with pytest.raises(StrkeyError) as excinfo:
        parse("")
    rendered = "".join(traceback.format_exception_only(excinfo.value))
    assert rendered.startswith("stellar_strkey.MalformedStrkeyError:")
