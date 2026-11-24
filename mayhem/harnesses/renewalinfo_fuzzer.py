#!/usr/bin/env python3
"""ACME Renewal Information (RFC 9773): op 0 is an unauthenticated GET of
/acme/renewal-info/<input> (CertID parsing from the URL path, DB lookup), op 1 POSTs the fuzz
payload ({"certID": ..., "replaced": ...}) to the renewal-info endpoint via Renewalinfo.update.

Renewalinfo.update does not validate the certID before decoding it: a non-object payload raises
TypeError, a badly padded / non-base64 certID raises binascii.Error (a ValueError), and a certID
without the 0x0420 marker raises ValueError (unpack), and a certID that decodes to valid UTF-8 raises
AttributeError (b64_decode returns str, then .hex()). Those are reported upstream findings (see
mayhem/renewalinfo_fuzzer/known-findings/); nearly every input reproduces one, so they are tolerated
here, only when raised from those exact sites (file, function, exception type and source line), so
the fuzzer gets past them instead of rediscovering them on every exec and the stored corpus does not
fail Mayhem's sanity probe. Any other exception,
or one of these types from any other line, is still a finding."""
import binascii
import linecache
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with atheris.instrument_imports(include=["acme2certifier", "a2c_fixture"]):
    import a2c_fixture as fx
    from acme2certifier.acme_srv.renewalinfo import Renewalinfo

fx.setup()
KNOWN_UPDATE_FINDINGS = (TypeError, ValueError, AttributeError, binascii.Error)
# Each known finding: (file, function, exact exception type, source line) of its innermost
# acme2certifier frame. The source text, not the line number, so the weekly upstream sync does not
# break the match; a new exception in the same function on any other line is still a finding.
KNOWN_SITES = {
    ("acme_srv/renewalinfo.py", "update", TypeError,
     'if "certid" not in payload or "replaced" not in payload:'),
    ("acme_srv/renewalinfo.py", "_extract_serial_and_aki_from_string", binascii.Error,
     "serial = base64.b64decode("),
    ("acme_srv/renewalinfo.py", "_extract_serial_and_aki_from_string", binascii.Error,
     "aki = base64.b64decode("),
    ("acme_srv/helpers/certificates.py", "certid_hex_get", binascii.Error,
     "renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()"),
    ("acme_srv/helpers/certificates.py", "certid_hex_get", AttributeError,
     "renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()"),
    ("acme_srv/helpers/certificates.py", "certid_hex_get", ValueError,
     'mda, certid_renewal = renewal_info_hex.split("0420", 1)'),
}


def _known(exc: BaseException) -> bool:
    site = None  # innermost acme_srv frame, skipping the b64 helper the error passes through
    tb = exc.__traceback__
    while tb is not None:
        fname = tb.tb_frame.f_code.co_filename
        if "/acme2certifier/acme_srv/" in fname and not fname.endswith("helpers/encoding.py"):
            site = (fname, tb.tb_frame.f_code.co_name, tb.tb_lineno)
        tb = tb.tb_next
    if site is None:
        return False
    fname, func, lineno = site
    rel = fname[fname.rindex("/acme_srv/") + 1:]
    line = linecache.getline(fname, lineno).strip()
    return (rel, func, type(exc), line) in KNOWN_SITES


def _post(proto_extra: dict, url: str, payload: bytes) -> str:
    protected = {"alg": "ES256", "nonce": "n", "url": url}
    protected.update(proto_extra)
    return fx.jws(protected, payload)



def TestOneInput(data: bytes) -> None:
    if not data:
        return -1
    op, payload = data[0] % 2, data[1:]
    fx.reset()
    with fx.Quiet(), Renewalinfo(False, fx.SERVER, fx.LOGGER) as ari:
        if op == 0:
            ari.get(fx.SERVER + "/acme/renewal-info/" + payload.decode("utf-8", errors="replace"))
        else:
            try:
                ari.update(_post({"kid": fx.KID}, fx.SERVER + "/acme/renewal-info", payload))
            except KNOWN_UPDATE_FINDINGS as exc:
                if not _known(exc):
                    raise
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
