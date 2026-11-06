# Security policy

## Supported versions

Security fixes are released for the latest version only. Upgrade to it before reporting
an issue.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue:

- Preferably through
  [GitHub's private vulnerability reporting](https://github.com/lightsail-network/py-stellar-strkey/security/advisories/new).
- Or by email to hi@overcat.dev. For GPG, see https://keybase.io/overcat.

Include the version, a minimal reproduction and what you think the impact is. Don't
include real secret seeds.

## Scope

Examples of what counts as a vulnerability:

- A secret seed appearing in `str()`, `repr()`, an error message or a generic
  serializer without being explicitly revealed.
- A strkey that isn't canonical according to SEP-23 being accepted, or a valid one
  being decoded to the wrong value.
- Input that makes decoding take much more time or memory than its length justifies.

The [guide](https://stellar-strkey.readthedocs.io/en/stable/guide/#private-keys)
describes known limits that are not considered vulnerabilities: Python can't erase
`bytes` from memory, base32 and CRC16 don't run in constant time, and the input string
itself is visible to the caller and in traceback local variables.
