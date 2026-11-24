#!/usr/bin/env python3
"""CSR helpers not reached by upstream's csr_fuzzer: CN/DN/subject/pubkey/extension getters,
unbound SAN types and the allowed-domain-list policy check a CSR is subjected
to at finalize. csr_san_byte_get is left out: no production code calls it. Input: CSR string, then (after a 0x00 byte) newline-separated allowed domains."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.helpers import csr as h
    from acme2certifier.acme_srv.helpers import domain_utils as d

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
EXPECTED = (ValueError, TypeError)


def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    flag = bool(data[0] & 1)
    text = data[1:].decode("utf-8", errors="replace")
    csr, _, allowed = text.partition("\x00")
    allowed_list = [x for x in allowed.split("\n") if x]
    for fn in (
        lambda: h.csr_cn_get(LOG, csr),
        lambda: h.csr_extra_cn_get(LOG, csr),
        lambda: h.csr_dn_get(LOG, csr),
        lambda: h.csr_pubkey_get(LOG, csr, encoding="pem" if flag else "base64der"),
        lambda: h.csr_extensions_get(LOG, csr),
        lambda: h.csr_subject_get(LOG, csr),
        lambda: h.csr_unbound_san_types(LOG, csr),
        lambda: h.csr_cn_lookup(LOG, csr),
        lambda: d.allowed_domainlist_check(LOG, csr, allowed_list, allow_shortname_from_fqdn=flag),
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
