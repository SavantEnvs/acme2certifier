#!/usr/bin/env python3
"""Certificate helpers not reached by upstream's cert_fuzzer: SAN/AKI/SKI/serial/dates/extension
getters, PEM bundle splitting, chain skip/append link checks and the ARI CertID builder.
Input: a certificate string (PEM or base64 DER); a second PEM is cut at a 0x00 byte if present.
Parse errors of a malformed certificate are the helpers' documented ValueError/TypeError contract."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.helpers import certificates as c

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
EXPECTED = (ValueError, TypeError)


def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    recode = bool(data[0] & 1)
    text = data[1:].decode("utf-8", errors="replace")
    cert, _, other = text.partition("\x00")
    for fn in (
        lambda: c.cert_san_get(LOG, cert, recode=recode),
        lambda: c.cert_bound_names_get(LOG, cert, recode=recode, email_identifier_rewrite=True),
        lambda: c.cert_aki_get(LOG, cert),
        lambda: c.cert_ski_get(LOG, cert),
        lambda: c.cert_dates_get(LOG, cert),
        lambda: c.cert_serial_get(LOG, cert, hexformat=recode),
        lambda: c.cert_extensions_get(LOG, cert, recode=recode),
        lambda: c.cert_cn_get(LOG, cert),
        lambda: c.cert_issuer_get(LOG, cert),
        lambda: c.cert_pubkey_get(LOG, cert),
        lambda: c.pembundle_to_list(LOG, text),
        lambda: c.cert_chain_skip(LOG, text, [other], link_check=recode),
        lambda: c.cert_chain_append(LOG, cert, [other], link_check=True, matching_only=recode),
        lambda: c.certid_asn1_get(LOG, cert, other),
    ):
        try:
            fn()
        except EXPECTED:
            pass
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
