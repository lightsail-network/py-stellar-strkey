"""Exceptions raised for input that is not an acceptable strkey.

`MalformedStrkeyError`, `ChecksumMismatchError` and `WrongStrkeyTypeError` are about a
string, so only `from_string` and `parse` raise them. Constructors and `from_bytes`
raise a plain `ValueError` for invalid key material, as Python's own constructors do,
because no string is involved there.

`UnsupportedVersionError` is about a version, so it is raised wherever one is read.
That is the version byte of a string, and the version of a claimable balance, which
is part of its binary form and so is read by `ClaimableBalance.from_bytes` as well.

Messages never contain the strkey or key material being processed, because the input
may be a secret seed and exception messages tend to end up in logs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._keys import Ed25519PrivateKey, Strkey


class StrkeyError(ValueError):
    """Base class of the errors raised for input that is not an acceptable strkey."""


class MalformedStrkeyError(StrkeyError):
    """The string is not a well-formed strkey.

    For example, it isn't canonical base32, or it has the wrong length or structure for
    its type. The message says what is wrong.
    """


class ChecksumMismatchError(MalformedStrkeyError):
    """The checksum does not match, which usually means the strkey was mistyped."""


class UnsupportedVersionError(StrkeyError):
    """The strkey's version is not one this package knows.

    Either its version byte is unknown, or it is a claimable balance of an unknown
    version. It may be a strkey type introduced after this release of the package.

    The version of a claimable balance is part of its binary form, so
    [`ClaimableBalance.from_bytes`][stellar_strkey.ClaimableBalance.from_bytes] raises
    this error too.
    """


class WrongStrkeyTypeError(StrkeyError):
    """The string is a strkey of another type than the one that was asked for.

    Only its encoding, checksum and version byte are checked. The rest is not, since the
    strkey would be rejected anyway.

    Attributes:
        expected: The type that was asked for, or `None` when
            [`parse`][stellar_strkey.parse] refused a private key, since it would have
            accepted any other type.
        found: The type of the strkey that was given.
    """

    expected: type[Strkey | Ed25519PrivateKey] | None
    found: type[Strkey | Ed25519PrivateKey]

    def __init__(
        self,
        expected: type[Strkey | Ed25519PrivateKey] | None,
        found: type[Strkey | Ed25519PrivateKey],
    ) -> None:
        # Passing the attributes to the base class keeps the exception picklable.
        super().__init__(expected, found)
        self.expected = expected
        self.found = found

    def __str__(self) -> str:
        if self.expected is None:
            return (
                "parse() does not return private keys; "
                f"use {self.found.__name__}.from_string"
            )
        return (
            f"expected a strkey of type {self.expected.__name__}, "
            f"got one of type {self.found.__name__}"
        )
