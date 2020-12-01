#! /usr/bin/env python3

import h5py
import sys
from pathlib import Path
import numpy as np
import math

#The fraction of the stats (from the beginning of it) that should be omitted
#This should be < 1 (<, not <=)
#If you want only the last dump, set it close to 1, e.g., 0.99999
warmup_percent = 0.5


def show_pretty_raw(number, fp_prec=1):    #This returns 23.1M instead of 23104123
    return number

    if number < 1000:
        return "%0.*f" % (fp_prec, number) 
    elif number < 1000000:
        return "%0.*fK" % (fp_prec, number/1000)
    elif number < 1000000000:
        return "%0.*fM" % (fp_prec, number/1000/1000)
    else:
        return "%0.*fB" % (fp_prec, number/1000/1000/1000)



def show_pretty_size(number, fp_prec=1):    #This returns 32KB instead of 23104123 
    return number

    if number < 1024:
        return "%0.*f" % (0, number) 
    elif number < 1024*1024:
        return "%0.*fK" % (fp_prec, number/1024)
    elif number < 1024*1024*1024:
        return "%0.*fM" % (fp_prec, number/1024/1024)
    else:
        return "%0.*fB" % (fp_prec, number/1024/1024/1024)



def show_pretty_percent(number, fp_prec=1):
    return number

    return "%0.*f" % (fp_prec, 100*number) + '%'



def get_stat_value(stat_pointer, parameter, begin_index=None):
    #stat_pointer: e.g., core stats, l1d stats, etc.
    #parameter: str, e.g., 'cycles', 'instrs', etc.
    #begin_index: int, from which dump onwards we care about the results

    if begin_index == None:
        begin_index = math.floor(len(stat_pointer[parameter]) * warmup_percent) - 1
    assert begin_index < len(stat_pointer[parameter]) - 1

    #This is an array of values, where every entry in array corresponds to a particular core
    return np.array(stat_pointer[parameter][-1]) - np.array(stat_pointer[parameter][begin_index])



if __name__ == "__main__":

    if (len(sys.argv[1:]) != 1):
        print("Wrong arguments!\nUsage: ./script path/to/experiment/folder")
        exit()

    result_files_list = list(Path(sys.argv[1]).glob('**/*zsim.h5'))

    for result_file in result_files_list:

        print("\nFile:", result_file)
        stats = h5py.File(result_file, 'r')
        stats = stats['stats']['root']

        #Simulation stats [Begin]
        stats_periods = len(stats['c']['cycles'])    #Number of dumps in zsim.h5 file during simulation
        whole_simulated_cycles = get_stat_value(stats['c'], 'cycles', begin_index=0) #Do include warmup
        whole_simulated_instructions = get_stat_value(stats['c'], 'instrs', begin_index=0)  #Do include warmup

        print("\nSimulation Stats:")
        #print("--Cycles:", show_pretty_raw(np.sum(whole_simulated_cycles)))
        #print("--Instructions:", show_pretty_raw(np.sum(whole_simulated_instructions)))
        #print("--Stats_Dumps:", show_pretty_raw(stats_periods, fp_prec=0))
        #print("--Warmup_Percent:", show_pretty_percent(warmup_percent))
        #Simulation stats [End]

        #Core stats [Begin]
        core_stats = stats['c']
        ##The following variables are all an array of stats with len == core count
        instructions = get_stat_value(core_stats, 'instrs')
        cycles = get_stat_value(core_stats, 'cycles')
        safeAppends = get_stat_value(core_stats, 'safeAppends')

        ipc = np.sum(instructions) / np.sum(cycles)

        print("\nCore Stats:")
        print('--IPC:', show_pretty_raw(ipc, fp_prec=2))
        print('--Instructions: ', show_pretty_raw(np.sum(instructions), fp_prec=0))
        print('--Cycles: ', show_pretty_raw(np.sum(cycles), fp_prec=0))
        print('--SafeAppends: ', show_pretty_raw(np.sum(safeAppends), fp_prec=0))
        #Core stats [End]

        print ('___________________________\n')

