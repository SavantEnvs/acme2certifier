#!/usr/bin/env python3
"""Identifier / contact validation applied to newOrder and newAccount payloads: validate_identifier
(dns/ip/email/tnauthlist), validate_email, FQDN/IP/CN checks and the allow-list pattern matchers.
Input: newline-separated fields [type, value, pattern...]. These functions return verdicts and must
not raise on any string."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.helpers import domain_utils as d
    from acme2certifier.acme_srv.helpers import validation as v

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False


def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    tnauth = bool(data[0] & 1)
    fields = data[1:].decode("utf-8", errors="replace").split("\n")
    id_type = fields[0]
    value = fields[1] if len(fields) > 1 else ""
    patterns = fields[2:]
    v.validate_identifier(LOG, id_type, value, tnauthlist_support=tnauth)
    v.validate_email(LOG, [value] + patterns)
    v.normalize_email_address(LOG, value)
    v.validate_fqdn(LOG, value)
    v.ip_validate(LOG, value)
    v.ipv6_chk(LOG, value)
    v.cn_validate(LOG, value)
    d.is_domain_whitelisted(LOG, value, patterns)
    d.is_email_whitelisted(LOG, value, patterns)
    d.is_shortname_denied(LOG, value, patterns)
    for pattern in patterns:
        d.pattern_check(LOG, value, pattern)
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
