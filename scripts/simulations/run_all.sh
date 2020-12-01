#! /usr/bin/env bash

echo "You may want to run with llvm-lit first to ensure all input files are created"
echo "Execute this script at 'build' directory."
echo "Current directory: $(pwd)"

find . -maxdepth 5 -name "*.test" | xargs cat | grep "PREPARE: " | while read line; do
    echo "Prepare command: $line"

    # Remove 'PREPARE: ' from the beginning of the commands.
    temp=$(echo "$line" | perl -pe 's/PREPARE: //')
    prep_command1=${temp%%;*}
    prep_command2=${temp##*;}

    $prep_command1
    $prep_command2
    cd - > /dev/null
done

ZSIM_BINARY="/users/mbakhsha/repos/zsim/zsim-bare/build/opt/zsim"
ZSIM_CONFIG="/users/mbakhsha/repos/zsim/zsim-bare/tests/cfi-ooo.cfg"
RES_DIR_PREFIX="$(pwd)/sim-res-model_sim-ref"

exp_counter=1
last_program_name=""

find . -maxdepth 5 -name "*.test" | xargs cat | grep "RUN: " | while read line; do
    # Measure the elapsed time
    SECONDS=0

    # Remove 'RUN: ' from the beginning of the commands.
    temp=$(echo "$line" | perl -pe 's/RUN: //')

    command1=${temp%%;*}
    command2=${temp##*;}

    # Remove '> file' from the command. Redirect program output to stdout.
    command2=$(echo "$command2" | perl -pe 's/>.+?(\s|$)//')

    # Extract program name (e.g., 400.perlbench) from the command.
    program_name=$(echo "$command2" | perl -pe 's/.*?(\d\d\d\..*?)(\s|\/).*/\1/')

    # Some programs are experimented more than once. Distinguish them by
    # assigning number to each experimented.
    if [[ $program_name == $last_program_name ]]; then
        exp_counter=$((exp_counter+1))
    else
        exp_counter=1
    fi
    experiment_name="$program_name.$exp_counter"
    last_program_name=$program_name

    RES_DIR="$RES_DIR_PREFIX/$experiment_name"

    if [ -d $RES_DIR ]; then
        echo "Skipping $experiment_name ..."
        continue
    fi
    echo "Running $experiment_name ..."

    mkdir -p $RES_DIR

    # The following command changes the current directory.
    $command1

    ln -sf $ZSIM_BINARY zsim 
    cp $ZSIM_CONFIG zsim_config.cfg

    # The content of ZSim config file should be changed.
    # command2 is used to run the benchamrk. We need to put it inside the
    # config file of ZSim.

    # ZSim doesn't like '< input_file' in the process command. We need to
    # remove it, and define an 'input' which determines the input file path.
    if [[ "$command2" == *\<* ]]; then
        input_path=$(echo "$command2" | perl -pe 's/.*<(.+?)(\s|$).*/\1/' | perl -pe 's/ //')
        command2=$(echo "$command2" | perl -pe 's/<.+?(\s|$)//')
        zsim_command="command = \"$command2\"; input = \"$input_path\";"
    else
        zsim_command="command = \"$command2\";"
    fi

    sed -i "s|command = \".*\";|$zsim_command|g" zsim_config.cfg

    ./zsim zsim_config.cfg > sim_log.txt 2>&1
    mv zsim-cmp.h5 zsim-ev.h5 zsim.h5 zsim.out out.cfg heartbeat sim_log.txt zsim_config.cfg $RES_DIR
    rm zsim

    cd - > /dev/null

    echo "`date` | Experiment: $experiment_name | Exec Time: $SECONDS seconds"
done

