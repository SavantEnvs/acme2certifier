#!/usr/bin/env python3
"""/trigger endpoint authentication (helpers/trigger_auth.py): the CA server's POST body and its
signature header are checked with trigger_hmac_verify, and a client certificate presented with the
request is walked to the configured trust anchor by trigger_cert_chain_verify (leaf + bundle PEM
parsing, issuer search, signature checks). Input: [body]\\x00[signature]\\x00[leaf PEM]\\x00[bundle PEM].
The trust anchor is a self-signed CA with a fixed key, generated once under $TMPDIR (read-only afterwards)."""
import datetime
import logging
import os
import sys
import tempfile

import atheris
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.helpers import trigger_auth as ta

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
KEYS = ["fuzz-hmac-key-1", "0123456789abcdef"]
# Fixed CA key (same as trigger_fuzzer.py) so the shipped seeds can carry a leaf it signed.
CA_KEY_INT = 0x5EED_CA_0001


def _make_ca() -> str:
    key = ec.derive_private_key(CA_KEY_INT, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a2c fuzz trigger CA")])
    start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=36500))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = os.path.join(tempfile.mkdtemp(prefix="a2c-trigger-"), "ca.pem")
    with open(path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return path


CA_PATH = _make_ca()


def TestOneInput(data: bytes) -> None:
    parts = data.split(b"\x00", 3) + [b"", b"", b""]
    body, sig, leaf, bundle = parts[0], parts[1], parts[2], parts[3]
    ta.trigger_hmac_verify(body, sig.decode("utf-8", errors="replace"), KEYS)
    ta.trigger_signature_from_headers({"X-A2C-Signature": sig.decode("utf-8", errors="replace")})
    ta.trigger_cert_chain_verify(
        LOG,
        leaf.decode("utf-8", errors="replace"),
        bundle.decode("utf-8", errors="replace") or None,
        CA_PATH,
    )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
