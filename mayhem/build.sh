#!/usr/bin/env bash
#
# mayhem/build.sh — build the acme2certifier Atheris fuzz targets (ELF launchers + standalone
# reproducers) and prepare the project's own pytest suite. Runs inside the commit image
# (mayhem/Dockerfile) as `mayhem` in /mayhem. Idempotent and air-gapped on re-run:
#   1. A wheelhouse under /opt/toolchains/python is filled ONCE (online, first build) with
#      acme2certifier's runtime deps + test/otel extras (read from pyproject.toml) + atheris,
#      pytest and impacket; the deps are then
#      installed OFFLINE (--no-index) into a fixed site dir. acme2certifier itself stays the editable
#      source tree (repo root on PYTHONPATH), so a patch under acme2certifier/ takes effect directly.
#   2. Each target gets an ELF launcher (Mayhem needs an ELF cmd; DWARF<4 via $DEBUG_FLAGS) that
#      execs python3 on mayhem/harnesses/<target>.py, plus an identical -standalone reproducer
#      (libFuzzer runs a file argument once).
#   3. run_tests.c -> acme2certifier_run_tests, the non-system ELF that test.sh runs pytest through.
# Atheris instruments the Python at import; SANITIZER_FLAGS only matters for native code, so the
# launchers (thin exec wrappers) are built with DEBUG_FLAGS only.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
export DEBUG_FLAGS CC MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"

PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
SITE="$PY_PREFIX/site"
mkdir -p "$WHEELHOUSE" "$SITE"
PY="$(command -v python3)"

# Runtime deps straight from upstream's pyproject.toml, plus what upstream CI installs for its
# pytest job (.github/workflows/quality-python.yml: `pip install ".[test,gssapi,otel]"` and
# `pip install pytest impacket`): the `test` and `otel` extras and impacket, plus atheris. The
# `gssapi` extra is left out: it compiles against libkrb5-dev, which the base image lacks, and the
# suite mocks gssapi where it uses it.
mapfile -t PKGS < <("$PY" -c 'import tomllib; p=tomllib.load(open("pyproject.toml","rb"))["project"]; print("\n".join(p["dependencies"] + p["optional-dependencies"]["test"] + p["optional-dependencies"]["otel"]))')
PKGS+=(atheris pytest impacket)

if ! ls "$WHEELHOUSE"/atheris-*.whl >/dev/null 2>&1; then
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  # `pip wheel` keeps binary wheels as-is and builds sdist-only packages into wheels, so the
  # offline (--no-index) install below resolves everything from the wheelhouse.
  "$PY" -m pip wheel --prefer-binary --wheel-dir "$WHEELHOUSE" "${PKGS[@]}"
else
  echo ">> wheelhouse already populated — reusing $WHEELHOUSE"
fi

if [ -f "$SITE/.installed" ]; then
  echo ">> deps already installed in $SITE — skipping"
else
  "$PY" -m pip install --no-index --find-links="$WHEELHOUSE" --target "$SITE" "${PKGS[@]}"
  touch "$SITE/.installed"
fi

PYTHONPATH="$SITE:$SRC" "$PY" -c 'import atheris, pytest, acme2certifier.acme_srv.helpers.csr; print("imports OK")'

TARGETS=(
  # upstream OSS-Fuzz harnesses (fuzz/*.py, run unchanged via mayhem/harnesses/<name>.py)
  cert_fuzzer certid_fuzzer csr_fuzzer jwk_signature_fuzzer jws_decode_fuzzer pkcs7_fuzzer tls_alpn_fuzzer
  # new targets
  cert_helpers_fuzzer csr_helpers_fuzzer validation_fuzzer config_fuzzer email_fuzzer
  dns_persist_fuzzer account_fuzzer order_fuzzer certificate_fuzzer renewalinfo_fuzzer
  challenge_fuzzer trigger_auth_fuzzer openssl_ca_fuzzer trigger_fuzzer
)
for t in "${TARGETS[@]}"; do
  h="$SRC/mayhem/harnesses/$t.py"
  [ -f "$h" ] || { echo "missing harness $h" >&2; exit 1; }
  $CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$h\"" mayhem/launcher.c -o "$SRC/$t"
  $CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$h\"" mayhem/launcher.c -o "$SRC/$t-standalone"
done

$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" mayhem/run_tests.c -o "$SRC/acme2certifier_run_tests"
echo ">> build.sh complete"
