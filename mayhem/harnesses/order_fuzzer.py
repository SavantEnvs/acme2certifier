#!/usr/bin/env python3
"""ACME newOrder requests (RFC 8555 7.4): the fuzz input is the JWS payload (identifiers, notBefore,
notAfter, profile) POSTed by the pre-registered account; Order.new validates identifiers, applies
the profile and creates order + authorization rows in the sqlite DB. First byte picks newOrder or a
POST to an order/finalize URL whose path is taken from the payload's "url" field."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.order import Order

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
    with fx.Quiet(), Order(False, fx.SERVER, fx.LOGGER) as order:
        if op == 0:
            order.new(_post({"kid": fx.KID}, fx.SERVER + "/acme/neworders", payload))
        else:
            path, _, body = payload.partition(b"\n")
            url = fx.SERVER + "/acme/order/" + path.decode("utf-8", errors="replace")
            order.parse(_post({"kid": fx.KID}, url, body))
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
