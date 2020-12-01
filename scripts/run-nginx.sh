#!/bin/bash

set -e

for i in {1..3}; do
  echo "Running iteration $i / 3"
  ./wrk --latency -t 1 -d 60s http://127.0.0.1:8080 > $1_$i.log 2>&1
  echo "Wrote $1_$i"
done
