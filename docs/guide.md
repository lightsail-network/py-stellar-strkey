# Guide

## Decode a strkey of a known type

Each strkey type has its own class. `from_string` accepts that type and nothing else, so
a contract address can't be mistaken for an account:

```python
from stellar_strkey import Contract, Ed25519PublicKey, WrongStrkeyTypeError

account = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

key = Ed25519PublicKey.from_string(account)
assert key.key.hex().startswith("3f0c34bf")
assert str(key) == account

assert not Contract.is_valid(account)
try:
    Contract.from_string(account)
except WrongStrkeyTypeError as error:
    expected, found = error.expected, error.found
assert (expected, found) == (Contract, Ed25519PublicKey)
```

## Decode a strkey of an unknown type

`parse()` returns the class that matches, ready for `match`:

```python
from stellar_strkey import Contract, Ed25519PublicKey, MuxedEd25519Account, parse

address = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"

match parse(address):
    case Ed25519PublicKey(key):
        description = f"account {key.hex()}"
    case MuxedEd25519Account(key, id):
        description = f"account {key.hex()}, muxed ID {id}"
    case Contract(hash):
        description = f"contract {hash.hex()}"
    case other:
        description = f"something else: {other!r}"

assert description.endswith("muxed ID 9223372036854775808")
```

`Strkey` is the union of every type `parse()` can return, so it works both as a type
annotation and with `isinstance`.

## Encode a strkey

Build the class from raw bytes and convert it with `str()`. Formatting works like it does
for the strkey string. The constructor validates what it is given, so an invalid strkey
can't be produced; like other Python constructors, it raises `ValueError` for invalid
values and `TypeError` for values of the wrong type.

The same 32 bytes give a different strkey for each type. This example uses the key from
the SEP-23 test cases:

```python
from stellar_strkey import Contract, Ed25519PublicKey, MuxedEd25519Account

key = bytes.fromhex("3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a")

assert str(Ed25519PublicKey(key)) == (
    "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
)
assert str(MuxedEd25519Account(key, id=0)) == (
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"
)
assert str(Contract(key)) == (
    "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA"
)
assert f"{Contract(key):>60}" == (
    "    CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA"
)

try:
    Ed25519PublicKey(key[:31])
except ValueError as error:
    message = str(error)
assert message == "key must be 32 bytes, got 31"
```

## Handle errors

Parsing a string raises a subclass of [`StrkeyError`][stellar_strkey.StrkeyError], which
is a `ValueError`. Each subclass stands for a different thing to tell the user:

| Error                                                          | Meaning                                            |
| -------------------------------------------------------------- | -------------------------------------------------- |
| [`ChecksumMismatchError`][stellar_strkey.ChecksumMismatchError] | The strkey was probably mistyped.                  |
| [`MalformedStrkeyError`][stellar_strkey.MalformedStrkeyError]   | It isn't a well-formed strkey. The message says why. |
| [`WrongStrkeyTypeError`][stellar_strkey.WrongStrkeyTypeError]   | It's a strkey of another type than expected.       |
| [`UnsupportedVersionError`][stellar_strkey.UnsupportedVersionError] | It may be a newer type than this package knows. |

`ChecksumMismatchError` is a kind of `MalformedStrkeyError`, so catch it first. The
specific reason, such as a wrong length or invalid padding, is in the message.

Decoding checks the input in this order: its overall length, its base32 encoding, the
checksum, the version byte, and then the payload. A parser for one type therefore raises
`WrongStrkeyTypeError` for any well-formed strkey of another type, even one whose payload
wouldn't fit the expected type. Input that isn't a well-formed strkey at all, such as one
longer than any type allows, raises `MalformedStrkeyError` first. The error says which
type was expected and which was found:

```python
from stellar_strkey import (
    ChecksumMismatchError,
    Ed25519PublicKey,
    MalformedStrkeyError,
    StrkeyError,
    WrongStrkeyTypeError,
)


def check_account(address: str) -> str:
    try:
        Ed25519PublicKey.from_string(address)
    except ChecksumMismatchError:
        return "That address has a typo."
    except MalformedStrkeyError:
        return "That is not a Stellar address."
    except WrongStrkeyTypeError as error:
        return f"That is a {error.found.__name__}, not an account."
    except StrkeyError:
        return "That address is not supported yet."
    return "OK"


assert check_account("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGA") == (
    "That address has a typo."
)
assert check_account("CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA") == (
    "That is a Contract, not an account."
)
```

Passing something that isn't a `str` is a programming error and raises `TypeError`
instead. Error messages never contain the input, because it might be a secret seed.

## Private keys

[`Ed25519PrivateKey`][stellar_strkey.Ed25519PrivateKey] redacts itself when rendered, so
logging one by accident reveals nothing. `reveal()` returns the strkey when you ask for
it explicitly:

```python
import pickle

from stellar_strkey import Ed25519PrivateKey, WrongStrkeyTypeError, parse

secret = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR"

key = Ed25519PrivateKey.from_string(secret)
assert str(key) == "<redacted>"
assert repr(key) == "Ed25519PrivateKey(<redacted>)"
assert key.reveal() == secret

try:
    parse(secret)
except WrongStrkeyTypeError as error:
    refused = error.found
assert refused is Ed25519PrivateKey

# Private keys can't be pickled. Store or send key.reveal() instead.
try:
    pickle.dumps(key)
except TypeError as error:
    message = str(error)
assert "use reveal()" in message
```

`parse()` never returns a private key, so code that handles arbitrary addresses can't
pick up a secret by accident. The error tells you that it was given one, which is worth
warning the user about. Input that starts with `S` but has an invalid encoding or
checksum is reported as malformed, like any other invalid input.

A private key is also kept out of generic serialization. Unlike the other types, it
isn't a dataclass and can't be pickled, so `dataclasses.asdict()`, msgspec, pydantic and
pickle can't write the seed out, even when the key sits inside your own data. To store or
send a key, use `reveal()` explicitly. `copy.copy()` and `copy.deepcopy()` return the key
itself, since it is immutable. Only `seed` and `to_bytes()` return the raw seed, so don't
log those.

!!! warning "Error trackers record local variables"

    When decoding a private key fails, the traceback's local variables still hold the
    string, both in this package's frames and in yours. Error trackers such as Sentry
    record local variables by default; turn that off (`include_local_variables=False`
    in Sentry) or scrub them wherever you parse secrets.

!!! warning "Limits of the protection"

    Python can't erase `bytes` from memory, and base32 and CRC16 don't run in constant
    time here. This doesn't protect against an attacker who can read process memory or
    measure decoding time precisely.

## Binary form

`to_bytes()` and `from_bytes()` convert to and from the binary form of a strkey, without
the version byte and checksum.

| Prefix | Class                  | Fields           | Binary form                           |
| ------ | ---------------------- | ---------------- | ------------------------------------- |
| `G`    | `Ed25519PublicKey`     | `key`            | 32-byte key                           |
| `S`    | `Ed25519PrivateKey`    | `seed`           | 32-byte seed                          |
| `M`    | `MuxedEd25519Account`  | `key`, `id`      | 32-byte key, 8-byte big-endian ID     |
| `P`    | `Ed25519SignedPayload` | `key`, `payload` | 32-byte key, XDR `opaque<64>` payload |
| `T`    | `PreAuthTx`            | `hash`           | 32-byte hash                          |
| `X`    | `HashX`                | `hash`           | 32-byte hash                          |
| `C`    | `Contract`             | `hash`           | 32-byte hash                          |
| `L`    | `LiquidityPool`        | `hash`           | 32-byte hash                          |
| `B`    | `ClaimableBalance`     | `hash`           | `0x00` version byte, 32-byte hash     |
| `W`    | `MuxedContract`        | `hash`, `id`     | 32-byte hash, 8-byte big-endian ID    |

`from_bytes()` raises `ValueError` for invalid input, like the constructors, except that
a claimable balance of an unknown version raises `UnsupportedVersionError`.
