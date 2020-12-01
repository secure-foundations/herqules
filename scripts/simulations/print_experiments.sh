#! /usr/bin/env bash

exp_counter=1
last_program_name=""

find . -maxdepth 5 -name "*.test" | xargs cat | grep "RUN: " | while read line; do
    # Remove 'RUN: ' from the beginning of the commands.
    temp=$(echo "$line" | perl -pe 's/RUN: //')

    command=${temp##*;}

    # Extract program name (e.g., 400.perlbench) from the command.
    program_name=$(echo "$command" | perl -pe 's/.*?(\d\d\d\..*?)(\s|\/).*/\1/')

    # Some programs are experimented more than once. Distinguish them by
    # assigning number to each experimented.
    if [[ $program_name == $last_program_name ]]; then
        exp_counter=$((exp_counter+1))
    else
        exp_counter=1
    fi
    experiment_name="$program_name.$exp_counter"
    last_program_name=$program_name

    echo "$experiment_name"
done

