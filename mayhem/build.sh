#!/usr/bin/env bash
#
# mayhem/build.sh — build the Record&Play fuzz harness, its standalone reproducer and the selftest.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Janus' configure is generated, not committed; autogen.sh is safe to re-run. It needs no network.
./autogen.sh >/dev/null

# Only the helper objects the harnesses and selftest need (same set as upstream fuzzers/config.sh).
JANUS_CONF="--disable-docs --disable-post-processing --disable-turn-rest-api --disable-all-transports \
 --disable-all-plugins --disable-all-handlers --disable-data-channels"
JANUS_OBJECTS="janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o janus-sdp-utils.o janus-config.o janus-record.o janus-apierror.o plugins/janus-plugin.o"
# Out-of-tree build dirs; /build is gitignored upstream so `git clean -ffdX` removes them all.
B="$SRC/build"
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# objects <dir> <cflags>: configure + build the helper objects in <dir>
objects() {
  local dir="$1" cflags="$2"
  mkdir -p "$dir"
  (cd "$dir" && env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="$cflags" $JANUS_CONF >/dev/null)
  make -C "$dir/src" -j"$MAYHEM_JOBS" $JANUS_OBJECTS
}
# Linked as an archive (like upstream's fuzzers/build.sh) so each harness only pulls the objects it
# needs: the rtp/rtcp harnesses do not define the globals janus-sdp-utils.o references.
objs() { local d="$1"; rm -f "$d/janus-lib.a"; (cd "$d/src" && ar rcs "$d/janus-lib.a" $JANUS_OBJECTS); printf '%s' "$d/janus-lib.a"; }

# 1) Sanitized project objects, instrumented for libFuzzer coverage, for the fuzz binaries.
objects "$B/fuzz" "$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
# 2) The same objects without coverage instrumentation, for the run-once standalone reproducers
#    (they link no fuzzer runtime, which the coverage callbacks would need).
objects "$B/standalone" "$FUZZ_CFLAGS"

DEPS_CFLAGS="$(pkg-config --cflags glib-2.0)"
DEPS_LIBS="$(pkg-config --libs glib-2.0 jansson zlib libconfig) -pthread -lm"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# The mined recordplay_fuzzer includes the Record&Play plugin source (its playout thread is static).
HARNESS_INC="-I$SRC/src -I$SRC/src/plugins"
for t in recordplay_fuzzer; do
  hsrc="$SRC/mayhem/$t.c"
  $CC $FUZZ_CFLAGS -fsanitize=fuzzer-no-link $DEPS_CFLAGS $HARNESS_INC -I"$B/fuzz" -c "$hsrc" -o "$B/fuzz/$t.o"
  $CC $FUZZ_CFLAGS -fsanitize=fuzzer-no-link $LIB_FUZZING_ENGINE "$B/fuzz/$t.o" "$B/lsan_off.o" \
      $(objs "$B/fuzz") $DEPS_LIBS -o "/mayhem/$t"
  $CC $FUZZ_CFLAGS $DEPS_CFLAGS $HARNESS_INC -I"$B/standalone" -c "$hsrc" -o "$B/standalone/$t.o"
  $CC $FUZZ_CFLAGS "$B/standalone/$t.o" "$B/standalone_main.o" "$B/lsan_off.o" \
      $(objs "$B/standalone") $DEPS_LIBS -o "/mayhem/$t-standalone"
done

# 3) Known-answer selftest with the project's NORMAL flags (no sanitizers), for mayhem/test.sh.
objects "$B/test" "-O2 $COVERAGE_FLAGS"
$CC -O2 $COVERAGE_FLAGS $DEPS_CFLAGS "$SRC/mayhem/selftest.c" $(objs "$B/test") $DEPS_LIBS \
    -o "$B/test/janus_selftest"
