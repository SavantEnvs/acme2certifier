# trigger_fuzzer: known findings (upstream, not seeds)

Found locally by `trigger_fuzzer` within seconds. Each is an uncaught exception out of `Trigger.parse()`
(`acme2certifier/acme_srv/trigger.py`) on an HMAC-authenticated `/trigger` POST, which the WSGI app
(`share/acme2certifier_wsgi.py` `trigger()`) does not catch, so the request ends in an HTTP 500 instead
of a 400 problem response:

| Exception | Site | Body |
|---|---|---|
| `ValueError: error parsing asn1 value` | `cahandlers/openssl_ca_handler.py` `_trigger_leaf_from_payload` (`cert_der2pem(der_bytes)`) → `helpers/certificates.py` `cert_der2pem` (`x509.load_der_x509_certificate`) | `{"payload": "QUJD"}` |
| `binascii.Error: Invalid base64-encoded string` | `cahandlers/openssl_ca_handler.py` `_trigger_leaf_from_payload` (`b64_decode(self.logger, payload)`) → `helpers/encoding.py` `b64_decode` | `{"payload": "A"}` |

The payload is base64-decoded unguarded, then tried as PEM inside a `try`; the DER fallback in the `except` branch is not
guarded, so any payload that is neither PEM nor DER certificate raises. The harness tolerates these
exceptions only at these sites (see its docstring). Reproduce against the upstream handler with the
`*.bin` files in this directory (the harness signs the body itself).
