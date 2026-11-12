"""One immutable class per strkey type, plus `parse` for unknown input."""

import hmac
import operator
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import (
    ClassVar,
    Final,
    NoReturn,
    Self,
    SupportsIndex,
    TypeAlias,
    TypeVar,
    cast,
    final,
)

from ._codec import decode, encode
from ._errors import (
    MalformedStrkeyError,
    StrkeyError,
    UnsupportedVersionError,
    WrongStrkeyTypeError,
)

_KEY_LEN: Final = 32
_ID_LEN: Final = 8
_LENGTH_PREFIX_LEN: Final = 4
_XDR_ALIGNMENT: Final = 4
_MAX_ID: Final = 2**64 - 1
_MIN_INNER_PAYLOAD_LEN: Final = 1
_MAX_INNER_PAYLOAD_LEN: Final = 64
_MUXED_PAYLOAD_LEN: Final = _KEY_LEN + _ID_LEN
_CLAIMABLE_BALANCE_V0: Final = b"\x00"

# SEP-23 version bytes: the key type in the top five bits, the algorithm in the rest.
_PUBLIC_KEY: Final = 6 << 3
_PRIVATE_KEY: Final = 18 << 3
_MUXED_ACCOUNT: Final = 12 << 3
_SIGNED_PAYLOAD: Final = 15 << 3
_PRE_AUTH_TX: Final = 19 << 3
_HASH_X: Final = 23 << 3
_CONTRACT: Final = 2 << 3
_LIQUIDITY_POOL: Final = 11 << 3
_CLAIMABLE_BALANCE: Final = 1 << 3
_MUXED_CONTRACT: Final = 22 << 3


def _require_bytes(name: str, value: bytes) -> bytes:
    """Return `value` as exact `bytes`, or raise `TypeError` if it isn't bytes."""
    # Coercing with bytes() would turn the integer 32 into 32 zero bytes.
    if not isinstance(value, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    # What is stored has to be exact bytes. A subclass can override __len__, __bool__
    # or __bytes__, or carry state of its own, so its content is copied out through
    # the buffer protocol. Exact bytes, the usual case, aren't copied.
    return value if type(value) is bytes else memoryview(value).tobytes()


def _require_len(name: str, value: bytes, length: int) -> bytes:
    value = _require_bytes(name, value)
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")
    return value


def _require_id(value: int) -> int:
    """Return `value` as an exact `int`, or raise if it isn't an unsigned 64-bit ID."""
    if not isinstance(value, int) or isinstance(value, bool):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"id must be int, got {type(value).__name__}")
    # Like bytes, what is stored has to be the exact type, not a subclass such as an
    # IntEnum member.
    value = operator.index(value)
    if not 0 <= value <= _MAX_ID:
        raise ValueError("id must fit in an unsigned 64-bit integer")
    return value


def _xdr_padding_len(length: int) -> int:
    return -length % _XDR_ALIGNMENT


_T = TypeVar("_T", bound="_Strkey")


def _from_payload(strkey_type: type[_T], payload: bytes) -> _T:
    try:
        return strkey_type.from_bytes(payload)
    except StrkeyError:
        raise
    except ValueError as error:
        # Invalid key material is a plain ValueError, but inside a strkey it means that
        # the strkey is malformed. The message never contains the input.
        raise MalformedStrkeyError(str(error)) from None


class _Strkey(ABC):
    """The operations shared by every strkey type, the private key included.

    Nothing here turns the binary form into text or into a pickle. That lives in
    `_Public`, which the private key does not inherit from, so a method added there
    cannot expose a seed.
    """

    __slots__ = ()

    _VERSION_BYTE: ClassVar[int]

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from the binary form of the strkey.

        Args:
            data: The binary form, in the layout `to_bytes` returns.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not a valid binary form for this type.
        """

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Return the binary form of the strkey, without version byte and checksum."""

    @classmethod
    def from_string(cls, value: str) -> Self:
        """Decode a strkey of exactly this type.

        Args:
            value: The strkey to decode.

        Raises:
            TypeError: If `value` is not a `str`.
            MalformedStrkeyError: If `value` is not a well-formed strkey.
            WrongStrkeyTypeError: If `value` is a strkey of another type.
            UnsupportedVersionError: If the version of `value` is unknown.
        """
        # The type is checked before its length, so an `M...` address given to a
        # `G...` parser is reported as the wrong type rather than as too long.
        version, payload = decode(value)
        if version != cls._VERSION_BYTE:
            # Only the ten types below are concrete, so cls is one of them.
            expected = cast("type[Strkey | Ed25519PrivateKey]", cls)
            raise WrongStrkeyTypeError(expected, _type_for_version_byte(version))
        return _from_payload(cls, payload)

    @classmethod
    def is_valid(cls, value: object) -> bool:
        """Return whether `value` is a valid strkey of exactly this type."""
        if not isinstance(value, str):
            return False
        try:
            cls.from_string(value)
        except StrkeyError:
            return False
        return True

    def __format__(self, format_spec: str) -> str:
        return format(str(self), format_spec)

    # Instances are immutable: __init__ sets the slots with object.__setattr__ and
    # nothing sets them afterwards.
    def __setattr__(self, name: str, _value: object, /) -> NoReturn:
        raise AttributeError(f"cannot assign to field {name!r}")

    def __delattr__(self, name: str, /) -> NoReturn:
        raise AttributeError(f"cannot delete field {name!r}")

    # An immutable value is its own copy. This also keeps copying a container that
    # holds a private key working, since a private key can't be pickled to copy it.
    # That includes dataclasses.asdict, which deep copies the values it doesn't
    # recurse into.
    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, _memo: dict[int, object], /) -> Self:
        return self


class _Public(_Strkey):
    """A strkey that is safe to show: every type except the private key.

    A strkey is a value with one canonical form, its string. These classes are written
    by hand rather than as dataclasses on purpose. Generic serializers (orjson, msgspec,
    pydantic and others) treat a dataclass as a record and write out its fields, here
    raw bytes, without calling the hook the caller gave them. A plain class is opaque
    to them: they refuse it or call that hook, and `str` is the right hook.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return encode(self._VERSION_BYTE, self.to_bytes())

    def __repr__(self) -> str:
        return f"{type(self).__name__}.from_string({str(self)!r})"

    # Two strkeys are equal when they have the same type and the same binary form,
    # which is to say when they are the same string.
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _Public) or type(other) is not type(self):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash((type(self), self.to_bytes()))

    # A pickle holds the binary form, which SEP-23 fixes, rather than the fields, and
    # loading one validates it like any other input.
    def __reduce__(self) -> tuple[Callable[[bytes], Self], tuple[bytes]]:
        return type(self).from_bytes, (self.to_bytes(),)


class _Hash(_Public):
    """A strkey whose binary form is a single 32-byte hash."""

    __slots__ = ("_hash",)
    __match_args__ = ("hash",)

    _hash: bytes

    def __init__(self, hash: bytes) -> None:
        object.__setattr__(self, "_hash", _require_len("hash", hash, _KEY_LEN))

    @property
    def hash(self) -> bytes:
        """The 32-byte hash."""
        return self._hash

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a 32-byte hash.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not 32 bytes long.
        """
        return cls(data)

    def to_bytes(self) -> bytes:
        """Return the 32-byte hash."""
        return self._hash


@final
class Ed25519PublicKey(_Public):
    """An ed25519 public key (`G...`)."""

    __slots__ = ("_key",)
    __match_args__ = ("key",)

    _VERSION_BYTE: ClassVar[int] = _PUBLIC_KEY
    _key: bytes

    def __init__(self, key: bytes) -> None:
        object.__setattr__(self, "_key", _require_len("key", key, _KEY_LEN))

    @property
    def key(self) -> bytes:
        """The 32-byte public key."""
        return self._key

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a 32-byte public key.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not 32 bytes long.
        """
        return cls(data)

    def to_bytes(self) -> bytes:
        """Return the 32-byte public key."""
        return self._key


_NOT_PICKLABLE: Final = (
    "cannot pickle Ed25519PrivateKey; use reveal() to store or send it explicitly"
)


@final
class Ed25519PrivateKey(_Strkey):
    """An ed25519 private key seed (`S...`).

    `str()`, `repr()` and f-strings are redacted, so a key cannot leak through logging
    by accident. Call [`reveal`][stellar_strkey.Ed25519PrivateKey.reveal] to get the
    strkey. Instances are immutable, compare in constant time and are unhashable.

    Like the other types, this is a plain class that tools which serialize objects
    generically, such as `dataclasses.asdict`, msgspec and pydantic, don't take apart.
    Unlike them, it also cannot be pickled, so none of those tools can write the seed
    out. To store or send a key, use `reveal`. `copy.copy` and `copy.deepcopy` return
    the key itself. Only `seed` and `to_bytes` return the raw seed, so don't log those.
    Python cannot erase `bytes` from memory, so this class does not protect against an
    attacker who can read process memory.
    """

    __slots__ = ("_seed",)
    __match_args__ = ("seed",)

    _VERSION_BYTE: ClassVar[int] = _PRIVATE_KEY
    _seed: bytes

    def __init__(self, seed: bytes) -> None:
        object.__setattr__(self, "_seed", _require_len("seed", seed, _KEY_LEN))

    @property
    def seed(self) -> bytes:
        """The 32-byte seed."""
        return self._seed

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a 32-byte seed.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not 32 bytes long.
        """
        return cls(data)

    def to_bytes(self) -> bytes:
        """Return the 32-byte seed."""
        return self._seed

    def reveal(self) -> str:
        """Return the secret `S...` strkey."""
        return encode(self._VERSION_BYTE, self._seed)

    def __str__(self) -> str:
        return "<redacted>"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PrivateKey):
            return NotImplemented
        return hmac.compare_digest(self._seed, other._seed)

    # Defining __eq__ already makes the class unhashable; this tells type checkers.
    __hash__: ClassVar[None]  # type: ignore[assignment]  # pyright: ignore[reportIncompatibleMethodOverride]

    # Pickling is refused because a pickle carries the seed to wherever it goes, such as
    # a cache, a task queue or a file, without the caller asking for that. cryptography
    # and pycryptodome also refuse to pickle private keys. Refusing can be relaxed later
    # without breaking anyone, while allowing it couldn't be taken back. To store or
    # send a key, use reveal().
    #
    # __getstate__ is refused as well because some serializers, such as jsonpickle,
    # call it directly instead of going through pickle.
    def __reduce_ex__(self, _protocol: SupportsIndex, /) -> NoReturn:
        raise TypeError(_NOT_PICKLABLE)

    def __getstate__(self) -> NoReturn:
        raise TypeError(_NOT_PICKLABLE)


@final
class MuxedEd25519Account(_Public):
    """A multiplexed ed25519 account (`M...`)."""

    __slots__ = ("_id", "_key")
    __match_args__ = ("key", "id")

    _VERSION_BYTE: ClassVar[int] = _MUXED_ACCOUNT
    _key: bytes
    _id: int

    def __init__(self, key: bytes, id: int) -> None:
        object.__setattr__(self, "_key", _require_len("key", key, _KEY_LEN))
        object.__setattr__(self, "_id", _require_id(id))

    @property
    def key(self) -> bytes:
        """The 32-byte public key of the underlying account."""
        return self._key

    @property
    def id(self) -> int:
        """The unsigned 64-bit multiplexing ID."""
        return self._id

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a public key followed by a big-endian ID.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not 40 bytes long.
        """
        data = _require_len("muxed account", data, _MUXED_PAYLOAD_LEN)
        return cls(data[:_KEY_LEN], int.from_bytes(data[_KEY_LEN:], "big"))

    def to_bytes(self) -> bytes:
        """Return the public key followed by the big-endian ID."""
        return self._key + self._id.to_bytes(_ID_LEN, "big")


@final
class Ed25519SignedPayload(_Public):
    """An ed25519 signed payload signer (`P...`, CAP-40)."""

    __slots__ = ("_key", "_payload")
    __match_args__ = ("key", "payload")

    _VERSION_BYTE: ClassVar[int] = _SIGNED_PAYLOAD
    _key: bytes
    _payload: bytes

    def __init__(self, key: bytes, payload: bytes) -> None:
        object.__setattr__(self, "_key", _require_len("key", key, _KEY_LEN))
        payload = _require_bytes("payload", payload)
        # stellar-core rejects empty payloads with SET_OPTIONS_BAD_SIGNER.
        if not _MIN_INNER_PAYLOAD_LEN <= len(payload) <= _MAX_INNER_PAYLOAD_LEN:
            raise ValueError(
                f"payload must be {_MIN_INNER_PAYLOAD_LEN} to "
                f"{_MAX_INNER_PAYLOAD_LEN} bytes, got {len(payload)}"
            )
        object.__setattr__(self, "_payload", payload)

    @property
    def key(self) -> bytes:
        """The 32-byte public key that has to sign the payload."""
        return self._key

    @property
    def payload(self) -> bytes:
        """The payload to sign, 1 to 64 bytes without padding."""
        return self._payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a public key and an XDR-encoded payload.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not a public key followed by a payload of 1 to 64
                bytes with its length prefix and zero padding.
        """
        data = _require_bytes("signed payload", data)
        payload_start = _KEY_LEN + _LENGTH_PREFIX_LEN
        min_len = payload_start + _XDR_ALIGNMENT
        max_len = payload_start + _MAX_INNER_PAYLOAD_LEN
        if not min_len <= len(data) <= max_len:
            raise ValueError(
                f"signed payload must be {min_len} to {max_len} bytes, got {len(data)}"
            )

        payload_len = int.from_bytes(data[_KEY_LEN:payload_start], "big")
        payload_end = payload_start + payload_len
        if payload_end + _xdr_padding_len(payload_len) != len(data):
            raise ValueError("signed payload length prefix does not match the data")
        if any(data[payload_end:]):
            raise ValueError("signed payload padding must be zero")
        return cls(data[:_KEY_LEN], data[payload_start:payload_end])

    def to_bytes(self) -> bytes:
        """Return the public key followed by the XDR-encoded payload."""
        length = len(self._payload)
        return b"".join(
            (
                self._key,
                length.to_bytes(_LENGTH_PREFIX_LEN, "big"),
                self._payload,
                bytes(_xdr_padding_len(length)),
            )
        )


@final
class PreAuthTx(_Hash):
    """A pre-authorized transaction hash signer (`T...`)."""

    __slots__ = ()
    _VERSION_BYTE: ClassVar[int] = _PRE_AUTH_TX


@final
class HashX(_Hash):
    """A SHA-256 hash signer, satisfied by revealing its preimage (`X...`)."""

    __slots__ = ()
    _VERSION_BYTE: ClassVar[int] = _HASH_X


@final
class Contract(_Hash):
    """A smart contract address (`C...`)."""

    __slots__ = ()
    _VERSION_BYTE: ClassVar[int] = _CONTRACT


@final
class LiquidityPool(_Hash):
    """A liquidity pool ID (`L...`)."""

    __slots__ = ()
    _VERSION_BYTE: ClassVar[int] = _LIQUIDITY_POOL


@final
class ClaimableBalance(_Hash):
    """A version 0 claimable balance ID (`B...`)."""

    __slots__ = ()
    _VERSION_BYTE: ClassVar[int] = _CLAIMABLE_BALANCE

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a version byte followed by a 32-byte hash.

        Raises:
            TypeError: If `data` is not `bytes`.
            UnsupportedVersionError: If the version byte is not 0.
            ValueError: If `data` is not 33 bytes long.
        """
        data = _require_bytes("claimable balance", data)
        if len(data) > 0 and data[:1] != _CLAIMABLE_BALANCE_V0:
            raise UnsupportedVersionError(
                f"unsupported claimable balance version {data[0]:#04x}"
            )
        data = _require_len(
            "claimable balance", data, len(_CLAIMABLE_BALANCE_V0) + _KEY_LEN
        )
        return cls(data[1:])

    def to_bytes(self) -> bytes:
        """Return the version byte followed by the 32-byte hash."""
        return _CLAIMABLE_BALANCE_V0 + self._hash


@final
class MuxedContract(_Public):
    """A multiplexed smart contract address (`W...`, CAP-84)."""

    __slots__ = ("_hash", "_id")
    __match_args__ = ("hash", "id")

    _VERSION_BYTE: ClassVar[int] = _MUXED_CONTRACT
    _hash: bytes
    _id: int

    def __init__(self, hash: bytes, id: int) -> None:
        object.__setattr__(self, "_hash", _require_len("hash", hash, _KEY_LEN))
        object.__setattr__(self, "_id", _require_id(id))

    @property
    def hash(self) -> bytes:
        """The 32-byte hash of the underlying contract."""
        return self._hash

    @property
    def id(self) -> int:
        """The unsigned 64-bit multiplexing ID."""
        return self._id

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Build an instance from a contract hash followed by a big-endian ID.

        Raises:
            TypeError: If `data` is not `bytes`.
            ValueError: If `data` is not 40 bytes long.
        """
        data = _require_len("muxed contract", data, _MUXED_PAYLOAD_LEN)
        return cls(data[:_KEY_LEN], int.from_bytes(data[_KEY_LEN:], "big"))

    def to_bytes(self) -> bytes:
        """Return the contract hash followed by the big-endian ID."""
        return self._hash + self._id.to_bytes(_ID_LEN, "big")


# Kept as a `TypeAlias` rather than a `type` statement, whose alias `isinstance()`
# does not accept.
Strkey: TypeAlias = (
    Ed25519PublicKey
    | MuxedEd25519Account
    | Ed25519SignedPayload
    | PreAuthTx
    | HashX
    | Contract
    | LiquidityPool
    | ClaimableBalance
    | MuxedContract
)
"""Every strkey type `parse` can return. Private keys are excluded on purpose.

`isinstance(value, Strkey)` works too.
"""

_TYPES_BY_VERSION_BYTE: Final[dict[int, type[Strkey | Ed25519PrivateKey]]] = {
    _PUBLIC_KEY: Ed25519PublicKey,
    _PRIVATE_KEY: Ed25519PrivateKey,
    _MUXED_ACCOUNT: MuxedEd25519Account,
    _SIGNED_PAYLOAD: Ed25519SignedPayload,
    _PRE_AUTH_TX: PreAuthTx,
    _HASH_X: HashX,
    _CONTRACT: Contract,
    _LIQUIDITY_POOL: LiquidityPool,
    _CLAIMABLE_BALANCE: ClaimableBalance,
    _MUXED_CONTRACT: MuxedContract,
}


def _type_for_version_byte(version: int) -> type[Strkey | Ed25519PrivateKey]:
    strkey_type = _TYPES_BY_VERSION_BYTE.get(version)
    if strkey_type is None:
        raise UnsupportedVersionError(f"unsupported version byte {version:#04x}")
    return strkey_type


def parse(value: str) -> Strkey:
    """Decode a strkey whose type is not known in advance.

    Private keys are refused, so input from an untrusted or generic source cannot
    silently become a secret. Use
    [`Ed25519PrivateKey.from_string`][stellar_strkey.Ed25519PrivateKey.from_string]
    for those.

    Args:
        value: The strkey to decode.

    Returns:
        An instance of the class that matches the strkey's type.

    Raises:
        TypeError: If `value` is not a `str`.
        MalformedStrkeyError: If `value` is not a well-formed strkey.
        WrongStrkeyTypeError: If `value` is a private key.
        UnsupportedVersionError: If the version of `value` is unknown.
    """
    version, payload = decode(value)
    strkey_type = _type_for_version_byte(version)
    if issubclass(strkey_type, Ed25519PrivateKey):
        raise WrongStrkeyTypeError(None, strkey_type)
    return _from_payload(strkey_type, payload)
