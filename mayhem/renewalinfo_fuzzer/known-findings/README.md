# renewalinfo_fuzzer: known findings (upstream, not seeds)

Found by Mayhem run `savantenvs/acme2certifier/renewalinfo-fuzzer/2` (the AttributeError row locally). All are uncaught exceptions
out of `Renewalinfo.update()` (`acme2certifier/acme_srv/renewalinfo.py`) on a malformed
renewal-info POST, which the WSGI app turns into an HTTP 500 instead of an ACME `malformed` problem:

| Exception | Site | Payload (op byte `0x01` + JSON) |
|---|---|---|
| `TypeError: argument of type 'int' is not iterable` | `renewalinfo.py:511` (`"certid" not in payload`) | `1` |
| `binascii.Error` (Incorrect padding / invalid length) | `renewalinfo.py:421/424` `_extract_serial_and_aki_from_string` | `{"certid":"ABC.A","replaced":true}` |
| `binascii.Error: Invalid base64 ... 1 more than a multiple of 4` | `helpers/certificates.py:740` `certid_hex_get` | `{"certid":"AAAAAAAAAAAAA","replaced":true}` |
| `ValueError: not enough values to unpack` | `helpers/certificates.py:743` `certid_hex_get` | `{"certid":"_w","replaced":true}` |
| `AttributeError: 'str' object has no attribute 'hex'` (found locally) | `helpers/certificates.py:740` `certid_hex_get` (`b64_decode` returns `str` for UTF-8 bytes) | `{"certid":"QUJD","replaced":true}` |

The harness tolerates these exception types only when raised from these sites (see its docstring), so they
are documented here instead of being rediscovered on every exec. Reproduce against the upstream
handler with the `*.bin` files in this directory.
