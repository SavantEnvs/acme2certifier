#!/usr/bin/env python3
"""The /trigger endpoint (acme_srv/trigger.py Trigger.parse): a CA server POSTs a JSON body
{"payload": <base64 PEM or DER certificate>} for an order that is still "processing". parse()
checks the HMAC signature header, decodes the JSON, hands the payload to the CA handler's trigger()
(acme2certifier/cahandlers/openssl_ca_handler.py: PEM/DER detection, chain build), rewrites the
bundle, walks the chain to [Trigger] ca_cert, matches the certificate's public key against the CSRs
of processing orders in the database and stores it.

Input: the raw POST body. The harness signs it with the configured HMAC key, as the real CA server
does, so the input gets past _auth_check (an unsigned body is only ever rejected with 403).

Once per process: the shared fixture (a2c_fixture.py) config + sqlite DB, extended with a [Trigger]
section and an issuing CA for the openssl handler, and its pending order moved to "processing" with
a CSR attached. The CA and leaf keys are fixed (derive_private_key) so the shipped seeds, which carry
a leaf certificate signed by that CA, match. fx.reset() restores the database before every input.

Known upstream findings, tolerated here only at their exact sites: the openssl handler's trigger()
base64-decodes the payload without catching binascii.Error, and treats a payload that is not PEM as
DER without catching the parse error (ValueError), so any authenticated trigger whose payload is not
base64 of a certificate raises out of parse() (an HTTP 500, not a 400). Nearly every mutated input
reproduces one; see mayhem/trigger_fuzzer/known-findings/. Any other exception, or these
from any other call site, is still a finding."""
import binascii
import configparser
import datetime
import hashlib
import hmac
import linecache
import os
import sqlite3
import shutil
import sys
import tempfile

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.helpers.config import load_config_cache_clear
    from acme2certifier.acme_srv.helpers.trigger_auth import TRIGGER_SIGNATURE_HEADER

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HMAC_KEY = "fuzz-trigger-hmac-key"
# Fixed keys: mayhem/trigger_fuzzer/testsuite was generated with the same values.
CA_KEY_INT = 0x5EED_CA_0001
LEAF_KEY_INT = 0x5EED_1EAF_0002
START = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)


def _ca(d: str):
    key = ec.derive_private_key(CA_KEY_INT, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a2c fuzz trigger CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(START).not_valid_after(START + datetime.timedelta(days=36500))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder().issuer_name(name)
        .last_update(START).next_update(START + datetime.timedelta(days=36500)).sign(key, hashes.SHA256())
    )
    paths = {n: os.path.join(d, n) for n in ("ca.key", "ca.pem", "ca.crl")}
    with open(paths["ca.key"], "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(paths["ca.pem"], "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(paths["ca.crl"], "wb") as fh:
        fh.write(crl.public_bytes(serialization.Encoding.PEM))
    return paths


def _csr_b64() -> str:
    import base64  # pylint: disable=import-outside-toplevel
    key = ec.derive_private_key(LEAF_KEY_INT, ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("www.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()


def _setup() -> None:
    fx.setup()
    d = tempfile.mkdtemp(prefix="a2c-trigger-")
    paths = _ca(d)
    cfg_file = os.environ["ACME_SRV_CONFIGFILE"]
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(cfg_file, encoding="utf-8")
    cfg["CAhandler"]["issuing_ca_key"] = paths["ca.key"]
    cfg["CAhandler"]["issuing_ca_cert"] = paths["ca.pem"]
    cfg["CAhandler"]["issuing_ca_crl"] = paths["ca.crl"]
    cfg["Trigger"] = {"enabled": "True", "hmac_keys": f'["{HMAC_KEY}"]', "ca_cert": paths["ca.pem"]}
    with open(cfg_file, "w", encoding="utf-8") as fh:
        cfg.write(fh)
    load_config_cache_clear()

    # Move the fixture's pending order to "processing" and attach the CSR, as finalize would.
    con = sqlite3.connect(fx._DB)  # pylint: disable=protected-access
    (order_id,) = con.execute("SELECT id FROM orders ORDER BY id LIMIT 1").fetchone()
    (status_id,) = con.execute("SELECT id FROM status WHERE name = 'processing'").fetchone()
    con.execute("UPDATE orders SET status_id = ? WHERE id = ?", (status_id, order_id))
    con.execute(
        "INSERT INTO certificate(name, csr, order_id, header_info) VALUES(?, ?, ?, '')",
        ("fuzzcert", _csr_b64(), order_id),
    )
    con.commit()
    con.close()
    shutil.copyfile(fx._DB, fx._PRISTINE)  # pylint: disable=protected-access


_setup()
with atheris.instrument_imports(include=["acme2certifier"]):
    from acme2certifier.acme_srv.trigger import Trigger


# (exception type, innermost acme2certifier frame, its caller) of each known finding, frames as
# (function, source line); the source text, not the line number, so the weekly upstream sync does not break the match.
KNOWN_SITES = {
    (ValueError,
     ("cert_der2pem", "cert = x509.load_der_x509_certificate(der_cert)"),
     ("_trigger_leaf_from_payload", "leaf_pem = convert_byte_to_string(cert_der2pem(der_bytes))")),
    (binascii.Error,
     ("b64_decode", "return convert_byte_to_string(base64.b64decode(string))"),
     ("_trigger_leaf_from_payload", "cert = b64_decode(self.logger, payload)")),
}


def _known(exc: BaseException) -> bool:
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        if "/acme2certifier/acme_srv/" in code.co_filename or "/acme2certifier/cahandlers/" in code.co_filename:
            frames.append((code.co_name, linecache.getline(code.co_filename, tb.tb_lineno).strip()))
        tb = tb.tb_next
    if len(frames) < 2:
        return False
    return (type(exc), frames[-1], frames[-2]) in KNOWN_SITES


def TestOneInput(data: bytes) -> int:
    if not data:
        return -1
    fx.reset()
    sig = hmac.new(HMAC_KEY.encode(), data, hashlib.sha256).hexdigest()
    with fx.Quiet(), Trigger(False, fx.SERVER, fx.LOGGER) as trigger:
        try:
            trigger.parse(data, {TRIGGER_SIGNATURE_HEADER: sig})
        except ValueError as exc:
            if not _known(exc):
                raise
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
