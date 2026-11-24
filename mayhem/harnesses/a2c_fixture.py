"""Shared in-process fixture for the acme2certifier request-handler targets.

Builds, once per process, a throw-away acme2certifier config + sqlite database under $TMPDIR and
points the server at it (ACME_SRV_CONFIGFILE). Nonce and JWS signature checks are disabled (the
documented `nonce_check_disable` / `signature_check_disable` test knobs, which only take effect with
ACME2CERTIFIER_I_KNOW_THE_RISK=1) so fuzz inputs reach the request parsing and business logic
instead of stopping at badNonce/badSignature. Challenge validation is disabled so no network I/O
happens. One account (KID below) is pre-registered in the pristine database.

State kept across inputs on purpose: the config (read-only) and the pristine database file, which
`reset()` copies over the working database before every input so each input sees the same rows.
"""
import base64
import json
import logging
import os
import shutil
import sys
import tempfile

SERVER = "http://localhost"
KID = None  # set by setup() to the Location of the pre-registered account
AUTHZ_URL = None  # authorization of the pre-created pending order (dns www.example.com)
CHALLENGE_URLS = []  # its challenges (http-01, dns-01, tls-alpn-01, ...)
# A fixed P-256 public JWK (RFC 7517 example key "1"); it is only stored, never used to verify.
JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
}

LOGGER = logging.getLogger("a2c-fuzz")
LOGGER.addHandler(logging.NullHandler())
LOGGER.setLevel(logging.CRITICAL)
LOGGER.propagate = False

_DIR = None
_DB = None
_PRISTINE = None


def b64u(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jws(protected: dict, payload, signature: str = "AAAA") -> str:
    """Flattened JWS JSON body as an ACME client would POST it."""
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    return json.dumps(
        {"protected": b64u(json.dumps(protected)), "payload": b64u(payload), "signature": signature}
    )


def setup() -> None:
    """Create config + db once; silence the security-gate banner and logging."""
    global _DIR, _DB, _PRISTINE, KID, AUTHZ_URL
    if _DIR is not None:
        return
    _DIR = tempfile.mkdtemp(prefix="a2c-fuzz-")
    _DB = os.path.join(_DIR, "acme_srv.db")
    _PRISTINE = os.path.join(_DIR, "pristine.db")
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.normpath(os.path.join(here, "..", ".."))
    cfg = os.path.join(_DIR, "acme_srv.cfg")
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write(
            "[DEFAULT]\ndebug: False\n\n"
            "[Nonce]\nnonce_check_disable: True\nsignature_check_disable: True\n\n"
            "[Account]\n\n"
            "[Order]\n\n"
            "[Certificate]\n\n"
            "[Challenge]\nchallenge_validation_disable: True\n\n"
            "[Directory]\n\n"
            "[Renewalinfo]\n\n"
            f"[DBhandler]\ndbfile: {_DB}\n\n"
            "[CAhandler]\n"
            f"handler_file: {repo}/acme2certifier/cahandlers/openssl_ca_handler.py\n"
        )
    os.environ["ACME_SRV_CONFIGFILE"] = cfg
    os.environ["ACME2CERTIFIER_I_KNOW_THE_RISK"] = "1"
    logging.disable(logging.CRITICAL)

    from acme2certifier.acme_srv.account import Account  # pylint: disable=import-outside-toplevel

    devnull = open(os.devnull, "w", encoding="utf-8")  # pylint: disable=consider-using-with
    out, err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = devnull
    try:
        with Account(False, SERVER, LOGGER) as acc:
            res = acc.new(
                jws(
                    {"alg": "ES256", "jwk": JWK, "nonce": "n", "url": SERVER + "/acme/newaccount"},
                    {"termsOfServiceAgreed": True, "contact": ["mailto:fuzz@example.com"]},
                )
            )
    finally:
        sys.stdout, sys.stderr = out, err
    if res.get("code") not in (200, 201):
        raise RuntimeError(f"fixture: account creation failed: {res}")
    KID = res["header"]["Location"]

    from acme2certifier.acme_srv.authorization import Authorization  # pylint: disable=import-outside-toplevel
    from acme2certifier.acme_srv.order import Order  # pylint: disable=import-outside-toplevel

    with Quiet(), Order(False, SERVER, LOGGER) as order:
        res = order.new(
            jws(
                {"alg": "ES256", "kid": KID, "nonce": "n", "url": SERVER + "/acme/neworders"},
                {"identifiers": [{"type": "dns", "value": "www.example.com"}]},
            )
        )
    if res.get("code") != 201:
        raise RuntimeError(f"fixture: order creation failed: {res}")
    AUTHZ_URL = res["data"]["authorizations"][0]
    # Fetching the authorization creates its challenges.
    with Quiet(), Authorization(False, SERVER, LOGGER) as authz:
        res = authz.new_post(
            jws({"alg": "ES256", "kid": KID, "nonce": "n", "url": AUTHZ_URL}, "")
        )
    for chall in res.get("data", {}).get("challenges", []):
        CHALLENGE_URLS.append(chall["url"])
    if not CHALLENGE_URLS:
        raise RuntimeError(f"fixture: no challenges created: {res}")
    shutil.copyfile(_DB, _PRISTINE)


def reset() -> None:
    """Restore the pristine database before an input."""
    shutil.copyfile(_PRISTINE, _DB)


class Quiet:
    """Silence the per-object security-gate banner on stdout/stderr."""

    def __enter__(self):
        self._out, self._err = sys.stdout, sys.stderr
        self._null = open(os.devnull, "w", encoding="utf-8")  # pylint: disable=consider-using-with
        sys.stdout = sys.stderr = self._null
        return self

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self._out, self._err
        self._null.close()
        return False
