# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/lightsail-network/py-stellar-strkey/compare/v0.1.0...v0.2.0) - 2026-11-12

### Breaking Changes

- The strkey types are plain classes, no longer dataclasses
  ([#3](https://github.com/lightsail-network/py-stellar-strkey/pull/3)). A generic
  serializer such as orjson, msgspec or pydantic used to take one apart and write out its
  fields as raw bytes. It now refuses a strkey or calls the hook you gave it, and `str` is
  the right hook. What changes for you:
  - `dataclasses.is_dataclass`, `fields`, `asdict` and `replace` no longer apply to these
    types.
  - Assigning to a field or deleting one raises `AttributeError` instead of
    `dataclasses.FrozenInstanceError`.
  - A pickle holds the binary form and is validated when loaded. Pickles written by 0.1.0
    cannot be loaded.
  - `hash()` depends on the type as well as the value, and `copy.copy()` and
    `copy.deepcopy()` return the instance itself.
- The ten strkey classes are final, so a type checker rejects a subclass of one.
- A `str` subclass that misreports its length is taken at its word. Decoding used to read
  its real content.

### Bug Fixes

- A muxed ID is always stored as a plain `int`. An `IntEnum` member used to be kept as it
  was.
- `WrongStrkeyTypeError.expected` and `found` are typed as strkey classes instead of
  `type[object]`, so `error.found.from_string(...)` type-checks.
- A string that decodes to invalid data says so. The message used to be the
  constructor's, such as `hash must be 32 bytes, got 33`, and is now
  `strkey decodes to invalid data: hash must be 32 bytes, got 33`.
- A decoding error no longer carries the input on an exception it replaced. That exception
  was not shown in tracebacks, but it was still attached. As a side effect, input with `=`
  padding is reported as not valid base32 rather than as not canonical.

### Refactoring

These change nothing you can observe, apart from which of two messages a signed payload
with several faults gets.

- Look up the type of a version byte in one place
- Check a signed payload's length prefix once
- Bound a signed payload by its own lengths

### Documentation

- State the order in which decoding checks a strkey ([#1](https://github.com/lightsail-network/py-stellar-strkey/pull/1))
- Give the values in the examples clear names ([#2](https://github.com/lightsail-network/py-stellar-strkey/pull/2))
- Say it is a Python library and title the docs py-stellar-strkey
- Catch `UnsupportedVersionError` by name in the error handling example
- Say what each `from_bytes` raises
- Say `UnsupportedVersionError` is about a version, not a string, which is why
  `ClaimableBalance.from_bytes` raises it too

## [0.1.0](https://github.com/lightsail-network/py-stellar-strkey/releases/tag/v0.1.0) - 2026-11-07

### Features

- Add stellar-strkey, a typed SEP-23 strkey library

