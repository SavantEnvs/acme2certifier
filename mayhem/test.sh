#!/usr/bin/env bash
#
# mayhem/test.sh — RUN acme2certifier's own test suite (deps already installed by
# mayhem/build.sh) and emit a CTRF (ctrf.io) summary. exit 0 iff failed==0. PATCH-grade oracle:
# a no-op patch that neuters the server breaks the suite's behavioral assertions (asserted
# return codes, ACME responses, parsed CSR/certificate fields, DB rows), so it FAILS here
# (anti-reward-hacking).
#
# It does NOT compile — build.sh installed pytest, the `test`/`otel` extras and impacket into the
# in-image site dir and compiled the acme2certifier_run_tests ELF wrapper. We only RUN the suite. The suite is
# routed through that compiled NON-system wrapper so the gate's sabotage check (neuter non-system
# binaries to exit(0)) actually perturbs the run (the CPython interpreter under /usr/bin would
# otherwise be spared).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
cd "$SRC"

# Put the in-image site dir (deps + pytest) and the acme2certifier source tree (repo root) on
# PYTHONPATH.
PY_PREFIX=/opt/toolchains/python
# shellcheck disable=SC1091
[ -f "$PY_PREFIX/env.sh" ] && source "$PY_PREFIX/env.sh"
export PYTHONPATH="$PY_PREFIX/site:$SRC${PYTHONPATH:+:$PYTHONPATH}"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/acme2certifier_run_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing/not executable — mayhem/build.sh must build it first" >&2
  emit_ctrf "pytest" 0 1 0
  exit 1
fi

# Upstream's whole pytest suite, run the way upstream CI runs it (.github/workflows/quality-python.yml:
# bare `pytest`, i.e. every test/test_*.py module in ONE process; pyproject.toml's `testpaths`).
# One process matters: test_hardening's Order/Account fixtures only work after earlier modules have
# set up config/DB state, so it errors when run alone (verified: 32 errors alone, 0 in the full run).
# `-o addopts=` only drops upstream's --cov flags (coverage reporting, not assertions).
#
# DESELECT lists the tests left out; each carries its verified reason:
#   test_crypto 046/047: their JWS fixture has a padded base64 signature ("...dHVyZU=") that
#   jwcrypto >= 1.6 rejects ("Invalid JWS Object [Invalid format]"). pyproject.toml leaves jwcrypto
#   unpinned, so the wheelhouse gets 1.6.x; both pass with jwcrypto 1.5.6 (verified). A test-data
#   issue against the current dependency, not a code defect.
DESELECT=(
  test/test_crypto.py::test_046_helper_decode_message
  test/test_crypto.py::test_047_helper_decode_message
)
args=(); for d in "${DESELECT[@]}"; do args+=(--deselect "$d"); done
LOG="$(mktemp)"
"$RUNNER" -p no:cacheprovider -o addopts= -q "${args[@]}" test/ >"$LOG" 2>&1
rc=$?
line="$(grep -E '^(=+ )?[0-9].*(passed|failed|error|skipped)' "$LOG" | tail -1)"
get() { echo "$line" | grep -oE "[0-9]+ $1" | grep -oE '^[0-9]+' | head -1; }
passed="$(get passed)"; f="$(get failed)"; e="$(get error)"; skipped="$(get skipped)"
passed="${passed:-0}"; f="${f:-0}"; e="${e:-0}"; skipped="${skipped:-0}"
failed=$(( f + e ))
grep -E '^(FAILED|ERROR) ' "$LOG" | head -50
echo "test.sh: pytest rc=$rc: $line"
# The suite did not run (no parseable counts), or pytest exited non-zero without counted failures.
if [ $(( passed + failed + skipped )) -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
  tail -40 "$LOG"; failed=$(( failed + 1 ))
fi
rm -f "$LOG"
emit_ctrf "pytest" "$passed" "$failed" "$skipped"
