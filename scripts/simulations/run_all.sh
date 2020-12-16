#! /usr/bin/env bash

echo "You may want to run with llvm-lit first to ensure all input files are created"
echo "Execute this script at 'build' directory."
echo "Current directory: $(pwd)"
echo "Usage: $0 METHOD_NAME CONCURRENT_JOBS"

ZSIM_BINARY="/proj/PrescriptiveMem/hw-ccfi/tests/zsim/build/opt/zsim"
ZSIM_CONFIG="/proj/PrescriptiveMem/hw-ccfi/tests/zsim/tests/cfi-ooo.cfg"

METHOD_NAME=${1?The method name (baseline, herqules) missing!}
CONCURRENT_JOBS=${2?The number of concurrent jobs missing!}

if [[ ! -f $ZSIM_BINARY ]]; then
    echo "Couldn't find zsim binary"
    exit 1
fi

if [[ ! -f $ZSIM_CONFIG ]]; then
    echo "Couldn't find zsim config file"
    exit 1
fi

RES_DIR_PREFIX="$(pwd)/sim-res-$METHOD_NAME-ref"

simulate() {
    sleep 1
    local CHANGE_DIRECTORY_COMMAND=$1
    local EXECUTION_COMMAND=$2
    local RESULT_DIRECTORY=$3
    local SIMULATION_NAME=$4

    local EXEC_PATH=$(echo "$CHANGE_DIRECTORY_COMMAND" | perl -pe 's/cd //')
    EXEC_PATH=$(echo "$EXEC_PATH" | perl -pe 's/ $//')

    local THE_ZSIM="zsim-$SIMULATION_NAME-$METHOD_NAME"
    local THE_CFG_FILE="zsim_config_$SIMULATION_NAME-$METHOD_NAME.cfg"

    ln -sf $ZSIM_BINARY $EXEC_PATH/$THE_ZSIM
    cp $ZSIM_CONFIG $EXEC_PATH/$THE_CFG_FILE

    # The content of ZSim config file should be changed.
    # EXECUTION_COMMAND is used to run the benchamrk. We need to put it inside the
    # config file of ZSim.

    # ZSim doesn't like '< input_file' in the process command. We need to
    # remove it, and define an 'input' which determines the input file path.
    local ZSIM_COMMAND
    if [[ "$EXECUTION_COMMAND" == *\<* ]]; then
        local INPUT_PATH=$(echo "$EXECUTION_COMMAND" | perl -pe 's/.*<(.+?)(\s|$).*/\1/' | perl -pe 's/ //')
        EXECUTION_COMMAND=$(echo "$EXECUTION_COMMAND" | perl -pe 's/<.+?(\s|$)//')
        ZSIM_COMMAND="command = \"$EXECUTION_COMMAND\"; input = \"$INPUT_PATH\";"
    else
        ZSIM_COMMAND="command = \"$EXECUTION_COMMAND\";"
    fi

    sed -i "s|command = \".*\";|$ZSIM_COMMAND|g" $EXEC_PATH/$THE_CFG_FILE

    THE_EXPERIMENT=$SIMULATION_NAME-$METHOD_NAME

    # The 'simulationName' parameter in the config file should be changed
    SIMULATION_NAME_COMMAND="simulationName = \"$THE_EXPERIMENT\";"
    sed -i "s|simulationName = \".*\";|$SIMULATION_NAME_COMMAND|g" $EXEC_PATH/$THE_CFG_FILE

    THE_CMP_H5_FILE="zsim-cmp_$THE_EXPERIMENT.h5"
    THE_EV_H5_FILE="zsim-ev_$THE_EXPERIMENT.h5"
    THE_H5_FILE="zsim_$THE_EXPERIMENT.h5"
    THE_OUT_STAT_FILE="zsim_$THE_EXPERIMENT.out"
    THE_OUT_CFG_FILE="out_$THE_EXPERIMENT.cfg"
    THE_HEARTBEAT_FILE="heartbeat_$THE_EXPERIMENT"
    THE_SIM_LOG_FILE="sim_log_$THE_EXPERIMENT.txt"
    # Measure the elapsed time
    SECONDS=0

    $CHANGE_DIRECTORY_COMMAND
    $EXEC_PATH/$THE_ZSIM $EXEC_PATH/$THE_CFG_FILE > $EXEC_PATH/$THE_SIM_LOG_FILE 2>&1
    mv $EXEC_PATH/$THE_CMP_H5_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_EV_H5_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_H5_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_OUT_STAT_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_OUT_CFG_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_HEARTBEAT_FILE $RESULT_DIRECTORY
    mv $EXEC_PATH/$THE_SIM_LOG_FILE $RESULT_DIRECTORY
    rm $EXEC_PATH/$THE_ZSIM
    rm $EXEC_PATH/$THE_CFG_FILE
    echo "`date` | Experiment: $SIMULATION_NAME | Exec Time: $SECONDS seconds"
}

find . -maxdepth 5 -name "*.test" | xargs cat | grep "PREPARE: " | while read line; do
    # Remove 'PREPARE: ' from the beginning of the commands.
    TEMP=$(echo "$line" | perl -pe 's/PREPARE: //')
    PREP_COMMAND1=${TEMP%%;*}
    PREP_COMMAND2=${TEMP##*;}

    $PREP_COMMAND1
    $PREP_COMMAND2
    cd - > /dev/null
done

EXP_COUNTER=1
LAST_PROGRAM_NAME=""

find . -maxdepth 5 -name "*.test" | xargs cat | grep "RUN: " | while read line; do
    JOBLIST=($(jobs -p))
    while (( ${#JOBLIST[*]} >= $CONCURRENT_JOBS ))
    do
        sleep 1
        JOBLIST=($(jobs -p))
    done

    # Remove 'RUN: ' from the beginning of the commands.
    TEMP=$(echo "$line" | perl -pe 's/RUN: //')

    COMMAND1=${TEMP%%;*}
    COMMAND2=${TEMP##*;}

    # Remove '> file' from the command. Redirect program output to stdout.
    COMMAND2=$(echo "$COMMAND2" | perl -pe 's/>.+?(\s|$)//')

    # Extract program name (e.g., 400.perlbench) from the command.
    PROGRAM_NAME=$(echo "$COMMAND2" | perl -pe 's/.*?(\d\d\d\..*?)(\s|\/).*/\1/')

    # Some programs are experimented more than once. Distinguish them by
    # assigning number to each experimented.
    if [[ $PROGRAM_NAME == $LAST_PROGRAM_NAME ]]; then
        EXP_COUNTER=$((EXP_COUNTER+1))
    else
        EXP_COUNTER=1
    fi
    EXPERIMENT_NAME="$PROGRAM_NAME.$EXP_COUNTER"
    LAST_PROGRAM_NAME=$PROGRAM_NAME

    RES_DIR="$RES_DIR_PREFIX/$EXPERIMENT_NAME"

    if [ -d $RES_DIR ]; then
        echo "Skipping $EXPERIMENT_NAME ..."
        continue
    fi
    echo "Running $EXPERIMENT_NAME ..."

    mkdir -p $RES_DIR

    simulate "$COMMAND1" "$COMMAND2" $RES_DIR $EXPERIMENT_NAME &
done

wait

exit 0

