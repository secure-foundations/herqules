ZSIM_RES_DIR=$1
ZSIM_RES_DIR=${ZSIM_RES_DIR%/}

grep "Failed assertion" ${ZSIM_RES_DIR}/*/sim_log.txt -iR

