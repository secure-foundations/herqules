#!/bin/sh

set -e

INPUT=`jq -r ".tests | map(.name | sub(\"test-suite :: External\";\"\")), map(.metrics.exec_time) | @csv" $1 | tr -d \"`
IFS=","
for f in $INPUT; do
    if [ -z "$f" ]; then
        echo -n ","
    else
        echo -n "`basename $f`,"
    fi
done
unset IFS
