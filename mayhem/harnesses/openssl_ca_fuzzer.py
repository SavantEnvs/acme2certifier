#!/usr/bin/env python3
"""acme2certifier's local OpenSSL CA backend (acme2certifier/cahandlers/openssl_ca_handler.py):
CAhandler.enroll signs the CSR an ACME client sends in its finalize request (CSR load, subject/SAN
copy, CN enforcement, allow/block domain lists, extension building, certificate store).
The input is the CSR string as the ACME finalize payload carries it (base64 DER, or PEM). revoke() is
not fuzzed: the server only hands it certificates it issued and found in its own database.

Once per process: a throw-away P-256 CA key/cert, an empty CRL and a cert store under $TMPDIR, and a
[CAhandler] config pointing at them (ACME_SRV_CONFIGFILE). The key, cert, CRL and config are read-only
afterwards; the cert store is emptied before every input. The handler reports bad CSRs as an error
string, so an exception out of enroll/revoke is a finding."""
import datetime
import logging
import os
import shutil
import sys
import tempfile

import atheris

with atheris.instrument_imports(include=["acme2certifier"]):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False


STORE = None


def _setup() -> None:
    global STORE  # pylint: disable=global-statement
    d = tempfile.mkdtemp(prefix="a2c-ossl-")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fuzz-ca")])
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder().issuer_name(name)
        .last_update(now).next_update(now + datetime.timedelta(days=36500)).sign(key, hashes.SHA256())
    )
    paths = {n: os.path.join(d, n) for n in ("ca.key", "ca.pem", "ca.crl")}
    with open(paths["ca.key"], "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(paths["ca.pem"], "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(paths["ca.crl"], "wb") as fh:
        fh.write(crl.public_bytes(serialization.Encoding.PEM))
    store = os.path.join(d, "certs")
    os.mkdir(store)
    STORE = store
    cfg = os.path.join(d, "acme_srv.cfg")
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write(
            "[DEFAULT]\ndebug: False\n\n[Order]\n\n"
            "[CAhandler]\n"
            f"issuing_ca_key: {paths['ca.key']}\nissuing_ca_cert: {paths['ca.pem']}\n"
            f"issuing_ca_crl: {paths['ca.crl']}\ncert_save_path: {store}\n"
            "cert_validity_days: 30\nblocked_domainlist: [\"*.bad.example\"]\n"
        )
    os.environ["ACME_SRV_CONFIGFILE"] = cfg
    logging.disable(logging.CRITICAL)


_setup()
with atheris.instrument_imports(include=["acme2certifier"]):
    from acme2certifier.cahandlers.openssl_ca_handler import CAhandler


def TestOneInput(data: bytes) -> int:
    if not data:
        return -1
    # enroll() writes <serial>.pem into cert_save_path; empty it so every input starts from the
    # same (empty) store and the disk does not fill over a long run.
    shutil.rmtree(STORE)
    os.mkdir(STORE)
    with CAhandler(False, LOG) as ca:
        ca.enroll(data.decode("utf-8", errors="replace"))
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
