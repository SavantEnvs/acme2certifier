#!/usr/bin/env python3
"""dns-persist-01 TXT record evaluation: the TXT data comes from the applicant's DNS zone during
challenge validation. Drives DnsPersistChallengeValidator._parse_issue_value and _evaluate_record
(issuer match, accounturi, policy=wildcard, persistUntil) on the raw record bytes."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.challenge_validators.dns_persist_validator import (
        DnsPersistChallengeValidator,
    )

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
VALIDATOR = DnsPersistChallengeValidator(LOG)
ACCOUNT = "http://localhost/acme/acct/fuzz"
ISSUERS = {"acme2certifier.example", "ca.example.net"}
NOW = 1767225600  # fixed clock so a result depends only on the input


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    wildcard = fdp.ConsumeBool()
    policy_wildcard = fdp.ConsumeBool()
    record = fdp.ConsumeBytes(fdp.remaining_bytes())
    VALIDATOR._parse_issue_value(record)  # pylint: disable=protected-access
    VALIDATOR._evaluate_record(  # pylint: disable=protected-access
        record.decode("utf-8", errors="replace"), ACCOUNT, ISSUERS, wildcard, policy_wildcard,
        lambda: NOW,
    )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
