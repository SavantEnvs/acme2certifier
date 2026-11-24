#!/usr/bin/env python3
"""ACME authorization and challenge requests (RFC 8555 7.5, 7.5.1): POSTs whose payload is the fuzz
input go to the pre-created pending authorization (op 0, Authorization.new_post), to one of its
challenges picked by the second byte (op 1, Challenge.parse: challenge lookup, status, keyAuthorization
and the validator registry with validation disabled, so no network I/O), or to a challenge URL whose
path is the first input line (op 2). The handlers return problem documents for bad requests, so an
exception out of them is a finding."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.authorization import Authorization
    from acme2certifier.acme_srv.challenge import Challenge

fx.setup()


def _post(url: str, payload: bytes) -> str:
    return fx.jws({"alg": "ES256", "kid": fx.KID, "nonce": "n", "url": url}, payload)


def TestOneInput(data: bytes) -> None:
    if len(data) < 2:
        return -1
    op, pick, payload = data[0] % 3, data[1], data[2:]
    fx.reset()
    with fx.Quiet():
        if op == 0:
            with Authorization(False, fx.SERVER, fx.LOGGER) as authz:
                authz.new_post(_post(fx.AUTHZ_URL, payload))
        else:
            if op == 1:
                url = fx.CHALLENGE_URLS[pick % len(fx.CHALLENGE_URLS)]
            else:
                path, _, payload = payload.partition(b"\n")
                url = fx.SERVER + "/acme/chall/" + path.decode("utf-8", errors="replace")
            with Challenge(False, fx.SERVER, fx.LOGGER) as chall:
                chall.parse(_post(url, payload))
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
