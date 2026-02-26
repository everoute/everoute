#!/bin/bash

# echo
set -x

# -v: pass -test.v and -v=1 to conntrack.test for verbose output (test + klog)
VERBOSE=""
while getopts "v" opt; do
    case $opt in
        v) VERBOSE="-test.v -v=1" ;;
    esac
done

# goto the script directory (conntrack package root)
cd "$(dirname "$0")"

rm -rf out
mkdir -p out

# Build from source directory so the conntrack package and its imports resolve correctly
go clean -testcache
go clean -cache
go test -c -gcflags=all="-N -l" -o out/conntrack.test .
if [ $? -ne 0 ]; then
    echo "go test build failed"
    exit 1
fi

cd out
perf record -g -F 200 --   ./conntrack.test   -test.run=NONE -test.bench=. -test.benchmem -test.memprofile mem.out $VERBOSE
if [ $? -ne 0 ]; then
    echo "perf record go test failed"
    exit 1
fi

# From conntrack/out/, tests/perf is at ../../../../../tests/perf
PERF_SCRIPT_DIR=../../../../../tests/perf

perf script -i perf.data > out.perf
$PERF_SCRIPT_DIR/stackcollapse-perf.pl out.perf > out.folded
grep -v 'initRandomConntrackFlows' out.folded > out.folded.filtered
$PERF_SCRIPT_DIR/flamegraph.pl out.folded.filtered > flamegraph.svg
