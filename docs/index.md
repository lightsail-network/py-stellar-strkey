# py-stellar-strkey

A Python library to encode and decode
[Stellar strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md),
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

## Install

```shell
pip install stellar-strkey
```

## At a glance

```python
from stellar_strkey import Ed25519PublicKey

address = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

# Decode an account ID into its raw ed25519 public key.
account = Ed25519PublicKey.from_string(address)
assert account.key.hex() == (
    "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"
)

# Encode the raw key back into the same account ID.
assert str(Ed25519PublicKey(account.key)) == address

# Validate user input. A mistyped character fails the checksum.
assert Ed25519PublicKey.is_valid(address)
assert not Ed25519PublicKey.is_valid(address[:-1] + "A")
```

Continue with the [guide](guide.md), or look things up in the
[API reference](api.md).
