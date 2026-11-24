#!/usr/bin/env python3
"""ACME certificate download and revocation (RFC 8555 7.4.2, 7.6): op 0 POSTs the fuzz payload to
revokeCert (payload.certificate is base64url DER, reason code), op 1 POSTs to a certificate URL
whose name is the first line of the input, op 2 is a GET of that URL. Runs Certificate's
revocation checks, cert lookup and the certificate_* business/repository layers on sqlite."""
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.certificate import Certificate

fx.setup()


def _post(proto_extra: dict, url: str, payload: bytes) -> str:
    protected = {"alg": "ES256", "nonce": "n", "url": url}
    protected.update(proto_extra)
    return fx.jws(protected, payload)



def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    op, payload = data[0] % 3, data[1:]
    fx.reset()
    with fx.Quiet(), Certificate(False, fx.SERVER, fx.LOGGER) as cert:
        if op == 0:
            cert.revoke(_post({"kid": fx.KID}, fx.SERVER + "/acme/revokecert", payload))
        else:
            path, _, body = payload.partition(b"\n")
            url = fx.SERVER + "/acme/cert/" + path.decode("utf-8", errors="replace")
            if op == 1:
                cert.new_post(_post({"kid": fx.KID}, url, body))
            else:
                cert.new_get(url)
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
