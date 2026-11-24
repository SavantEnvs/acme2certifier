#!/usr/bin/env python3
"""Inbound e-mail parsing for the RFC 8823 email-reply-00 challenge: the raw message (attacker
mail fetched over IMAP) is parsed by EmailHandler._email_parse (headers, multipart, attachments)
and its body is scanned by EmailReplyChallengeValidator._extract_email_keyauth."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import email
import email.policy
import logging

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    from acme2certifier.acme_srv.challenge_validators.email_reply_validator import (
        EmailReplyChallengeValidator,
    )
    from acme2certifier.acme_srv.email_handler import EmailHandler

LOG = logging.getLogger("fuzz")
LOG.addHandler(logging.NullHandler())
LOG.setLevel(logging.CRITICAL)
LOG.propagate = False
HANDLER = EmailHandler(logger=LOG)
VALIDATOR = EmailReplyChallengeValidator(LOG)


def TestOneInput(data: bytes) -> None:
    # Same call the IMAP fetch loop makes on every fetched RFC822 message.
    msg = email.message_from_bytes(data)
    parsed = HANDLER._email_parse(msg)  # pylint: disable=protected-access
    VALIDATOR._extract_email_keyauth(parsed.get("body"))  # pylint: disable=protected-access
    VALIDATOR._extract_message_ids(  # pylint: disable=protected-access
        str(msg.get("In-Reply-To", "")), str(msg.get("References", ""))
    )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
