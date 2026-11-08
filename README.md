# stellar-strkey

Encode and decode [Stellar strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md),
the `G...`, `C...` and `M...` strings that identify accounts, contracts, signers and
other things on the Stellar network.

- **Complete.** Supports every strkey type defined by SEP-23.
- **Strict.** Accepts a strkey only in its one canonical form and rejects everything else
  with a clear error, so invalid input never gets through.
- **Thoroughly tested.** Verified against the SEP-23 test cases and a shared set of test
  vectors, with property-based tests and 100% branch coverage.
- **Safe with secrets.** Secret seeds are never printed or serialized by accident, and
  error messages never include the input.
- **Lightweight.** Fully typed, pure Python, no dependencies.

The [documentation](https://stellar-strkey.readthedocs.io/) has the guide and the API
reference.

## Install

```shell
pip install stellar-strkey
```

## Usage

```python
from stellar_strkey import (
    Contract,
    Ed25519PublicKey,
    MuxedEd25519Account,
    StrkeyError,
    parse,
)

# When you know the type, use its class. Anything else is rejected.
account = Ed25519PublicKey.from_string(
    "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
)
assert account.key.hex() == (
    "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"
)
# The same 32 bytes as a contract give a different strkey.
assert str(Contract(account.key)) == (
    "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA"
)

# When you don't, parse() returns the matching class.
match parse("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"):
    case Ed25519PublicKey(key):
        description = f"account {key.hex()}"
    case MuxedEd25519Account(key, muxed_id):
        description = f"muxed account {key.hex()} with ID {muxed_id}"
    case other:
        description = f"something else: {other!r}"
assert description.endswith("with ID 9223372036854775808")

# Invalid input raises StrkeyError, which is a ValueError.
try:
    parse("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGA")
except StrkeyError as error:
    message = str(error)
assert message == "strkey checksum does not match"
```

### Secret seeds

Secret seeds (`S...`) have their own parser, and `parse()` refuses them, so code that
handles arbitrary addresses can't pick up a secret by accident:

```python
from stellar_strkey import Ed25519PrivateKey, WrongStrkeyTypeError, parse

# In real code, load the secret from the environment or a secret store, never from
# source code. This is a well-known test seed.
secret = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR"

private_key = Ed25519PrivateKey.from_string(secret)
seed = private_key.seed  # the raw 32 bytes, for example for an ed25519 signing library
assert len(seed) == 32

# Printing or logging the key never shows the seed.
assert str(private_key) == "<redacted>"
assert repr(private_key) == "Ed25519PrivateKey(<redacted>)"

# Get the strkey back only where you mean to.
assert private_key.reveal() == secret

try:
    parse(secret)
except WrongStrkeyTypeError as error:
    refused = error.found
assert refused is Ed25519PrivateKey
```

## Types

| Prefix | Class                  | Fields           | `to_bytes()` / `from_bytes()` layout  |
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

See the guide for how to handle errors, and for what private keys are protected
against and what they aren't.

## Development

```shell
uv sync --all-groups       # create the environment, including the docs tools
uv run prek install        # optional: check before each commit
make check                 # format check, lint, type checks and tests with coverage
make docs-serve            # preview the documentation
```

`tests/vectors/strkeys.json` holds the shared test vectors in a language neutral form.
Add new cases there by hand, with the expected result that SEP-23 requires.

To release, run `make release-prep VERSION=<version>`, which sets the version and adds the
commits since the last release to `CHANGELOG.md`. Edit the new section where a commit
title isn't enough, commit it, then push a `v<version>` tag. The publish workflow verifies
that the tag matches the version and publishes to PyPI with trusted publishing, along with
PEP 740 attestations.

## License

[Apache-2.0](https://github.com/lightsail-network/py-stellar-strkey/blob/main/LICENSE)
