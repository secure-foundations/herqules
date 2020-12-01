#! /usr/bin/env bash

# This script checks whether all workloads of CFI experiments are simulated
# (i.e., there's a directory for every workload in the RESULT directory)

if [ ! -f print_experiments.sh ]; then
    echo "print_experiments.sh does not exist in the current directory!"
fi

if [ ! -f ~/bin/cfi_interesting_stats.py ]; then
    echo "cfi_interesting_stats.py does not exist in the bin directory!"
fi

diff <(cfi_interesting_stats.py $1 | grep "File" | perl -pe 's/.*(\d\d\d\..*?\.\d).*$/\1/' ) <(./print_experiments.sh )

exit 0
