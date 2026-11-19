#!/usr/bin/env bash
#
# mayhem/test.sh — runs upstream's googletest suites for the fuzzed codecs (base64, range coder,
# ANS32, Iguana), built by mayhem/build.sh into build/mayhem-test/tests. Each suite checks
# known-answer encodings and round trips; counts come from gtest's own summary lines, so a
# binary that exits 0 without running its tests counts as failed.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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


TESTS_DIR="$SRC/build/mayhem-test/tests"
passed=0; failed=0; skipped=0
for t in base64_test range_coder_test ans_test iguana_test; do
  bin="$TESTS_DIR/$t"
  if [ ! -x "$bin" ]; then
    echo "missing test binary $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  log="$(mktemp)"
  "$bin" >"$log" 2>&1; rc=$?
  ran=$(sed -n 's/^\[==========\] \([0-9][0-9]*\) tests\{0,1\} from .* ran\..*/\1/p' "$log" | tail -1)
  ok=$(sed -n 's/^\[  PASSED  \] \([0-9][0-9]*\) tests\{0,1\}\..*/\1/p' "$log" | tail -1)
  sk=$(sed -n 's/^\[  SKIPPED \] \([0-9][0-9]*\) tests\{0,1\}, listed below.*/\1/p' "$log" | tail -1)
  ran=${ran:-0}; ok=${ok:-0}; sk=${sk:-0}
  bad=$(( ran - ok - sk ))
  if [ "$rc" -ne 0 ] || [ "$ran" -eq 0 ]; then
    # crashed, aborted or produced no gtest summary: count at least one failure
    [ "$bad" -gt 0 ] || bad=1
    tail -n 30 "$log" >&2
  fi
  echo "$t: ran=$ran passed=$ok skipped=$sk failed=$bad (exit $rc)"
  passed=$((passed + ok)); skipped=$((skipped + sk)); failed=$((failed + bad))
  rm -f "$log"
done
emit_ctrf "googletest" "$passed" "$failed" "$skipped"
