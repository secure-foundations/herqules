#!/bin/bash

set -e

export ASAN_SYMBOLIZER_PATH=`dirname "$0"`/llvm/llvm-project/llvm/build_release/bin/llvm-symbolizer
export ASAN_OPTIONS=alloc_dealloc_mismatch=0:detect_leaks=0:halt_on_error=0

for i in {1..3}; do
  find . -name "Output" -type d -exec rm -r {} \; || true
  echo "Running iteration $i / 3"
  ../../../llvm/llvm-project/llvm/build_release/bin/llvm-lit External/ -j1 --timeout $2 > $1_$i.stdout 2>&1
  ../../../scripts/combine.py External
  mv External/out.csv $1_$i.csv
  mv test.log $1_$i.log
  echo "Wrote $1_$i"
  sleep 1s
done
