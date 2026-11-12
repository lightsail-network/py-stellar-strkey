"""The strkey wire format: `base32(version || payload || crc16-xmodem)`."""

import base64
import binascii
from typing import Final

from ._errors import ChecksumMismatchError, MalformedStrkeyError

_VERSION_LEN: Final = 1
_CHECKSUM_LEN: Final = 2
_BASE32_BLOCK_LEN: Final = 8

# The length is checked before decoding, so that hostile input is rejected without being
# decoded. The cost is that a future strkey type with a longer payload would be reported
# as malformed rather than as an unsupported version until this limit is raised for it.
MAX_PAYLOAD_LEN: Final = 100
"""The largest payload of any type: a signed payload with a 64-byte inner payload."""

# The padding standard base32 needs for each valid remainder of the encoded length.
# Lengths congruent to 1, 3 or 6 mod 8 cannot be produced by any byte sequence.
_PADDING_BY_REMAINDER: Final = {0: 0, 2: 6, 4: 4, 5: 3, 7: 1}


def _checksum(data: bytes) -> bytes:
    return binascii.crc_hqx(data, 0).to_bytes(_CHECKSUM_LEN, "little")


def encode(version: int, payload: bytes) -> str:
    """Encode a version byte and a payload into a strkey."""
    data = bytes((version,)) + payload
    return base64.b32encode(data + _checksum(data)).rstrip(b"=").decode("ascii")


def decode(value: str) -> tuple[int, bytes]:
    """Decode a strkey into its version byte and payload.

    The length is checked before any decoding happens, which bounds the work done
    on hostile input. SEP-23 only accepts a strkey that re-encodes to exactly the
    same string, which also rejects padding, lower case and non-zero trailing bits.

    Args:
        value: The strkey to decode.

    Returns:
        The version byte and the payload.

    Raises:
        TypeError: If `value` is not a `str`.
        MalformedStrkeyError: If `value` is not a well-formed strkey.
    """
    if not isinstance(value, str):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(f"strkey must be str, got {type(value).__name__}")

    padding = _PADDING_BY_REMAINDER.get(len(value) % _BASE32_BLOCK_LEN)
    if padding is None:
        raise MalformedStrkeyError("strkey has an impossible base32 length")

    data_len = len(value) * 5 // 8
    if data_len < _VERSION_LEN + _CHECKSUM_LEN:
        raise MalformedStrkeyError(
            "strkey is too short to hold a version and a checksum"
        )
    if data_len > _VERSION_LEN + MAX_PAYLOAD_LEN + _CHECKSUM_LEN:
        raise MalformedStrkeyError(
            f"strkey payload exceeds {MAX_PAYLOAD_LEN} bytes, the most of any type"
        )

    try:
        encoded = value.encode("ascii")
        data = base64.b32decode(encoded + b"=" * padding)
    except ValueError:  # UnicodeEncodeError and binascii.Error
        raise MalformedStrkeyError("strkey is not valid base32") from None
    if base64.b32encode(data).rstrip(b"=") != encoded:
        raise MalformedStrkeyError("strkey is not canonical base32")

    if _checksum(data[:-_CHECKSUM_LEN]) != data[-_CHECKSUM_LEN:]:
        raise ChecksumMismatchError("strkey checksum does not match")
    return data[0], data[_VERSION_LEN:-_CHECKSUM_LEN]
