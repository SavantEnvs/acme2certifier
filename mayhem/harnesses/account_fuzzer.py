#!/usr/bin/env python3
"""ACME newAccount and account-update requests (RFC 8555 7.3): a flattened JWS whose payload is the
fuzz input goes through Message.check (JWS decode, protected-header and url checks, account lookup)
and the Account handler (contact validation, ToS, EAB, key rollover, deactivation) against a sqlite
DB. First byte picks newAccount (jwk) or a POST to the pre-registered account URL (kid). The
handler returns problem documents for bad requests, so an exception out of it is a finding."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.account import Account

fx.setup()


def _post(proto_extra: dict, url: str, payload: bytes) -> str:
    protected = {"alg": "ES256", "nonce": "n", "url": url}
    protected.update(proto_extra)
    return fx.jws(protected, payload)



def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    op, payload = data[0] % 2, data[1:]
    fx.reset()
    with fx.Quiet(), Account(False, fx.SERVER, fx.LOGGER) as acc:
        if op == 0:
            acc.new(_post({"jwk": fx.JWK}, fx.SERVER + "/acme/newaccount", payload))
        else:
            acc.parse(_post({"kid": fx.KID}, fx.KID, payload))
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
