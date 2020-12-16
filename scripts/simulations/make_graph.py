#! /usr/bin/env python3

import h5py
import sys
from pathlib import Path
import numpy as np
import math
import re

import matplotlib
import matplotlib.pyplot as plt

import pickle

# PRINT_NUMBERS = False
PRINT_NUMBERS = True

SHOW_GRAPH = False
# SHOW_GRAPH = True

# The number of instructions for every single safeAppend event
CFI_INSTRUCTIONS = 8

# The fraction of the stats (from the beginning) that should be omitted. This
# should be < 1. If you want only the last dump, set it close to 1, e.g., 0.999
WARMUP_PERCENT = 0.5


def get_stat_value(stat_pointer, parameter, begin_index=None):
    # stat_pointer: e.g., core stats, l1d stats, etc.
    # parameter: str, e.g., 'cycles', 'instrs', etc.
    # begin_index: int, from which dump onwards we care about the results

    if begin_index == None:
        begin_index = max(0, math.floor(len(stat_pointer[parameter]) * WARMUP_PERCENT) - 1)
    assert begin_index < len(stat_pointer[parameter]) - 1

    # This is an array of values with len() == core count, where every entry in
    # array corresponds to a particular core
    return np.array(stat_pointer[parameter][-1]) - np.array(stat_pointer[parameter][begin_index])



def divide_stats(a, b):
    if np.sum(b) == 0: return -1
    return np.sum(a) / np.sum(b)



def get_app_ipc(stat_file):
    """
    Returns application IPC (and not pure IPC). I.e., CFI instructions are
    are considered "non-application" instructions and are excluded from
    performance measurements.
    """
    stats = h5py.File(stat_file, 'r')
    stats = stats['stats']['root']
    core_name = 'c'
    core_stats = stats[core_name]
    stats_periods = len(core_stats)    # Number of dumps in zsim_*.h5 file during simulation
    whole_simulated_instructions = get_stat_value(core_stats, 'instrs', begin_index=0)  # Do include warmup

    instructions = get_stat_value(core_stats, 'instrs')
    cycles = get_stat_value(core_stats, 'cycles')
    safe_appends = get_stat_value(core_stats, 'safeAppends')
    app_instructions = instructions - safe_appends * CFI_INSTRUCTIONS
    ipc = divide_stats(instructions, cycles)
    app_ipc = divide_stats(app_instructions, cycles)

    return app_ipc



def read_stat_files(path1, path2):
    stat_file_pattern = '**/zsim_*.h5'
    baseline = list(sorted(Path(path1).glob(stat_file_pattern)))
    herqules = list(sorted(Path(path2).glob(stat_file_pattern)))
    assert len(baseline) == len(herqules)
    num_benchmarks = len(baseline)

    all_benchmark_name = []
    all_baseline_app_ipc = []
    all_herqules_app_ipc = []

    benchmark_pattern = '^.*(\d\d\d\..*\.\d)\/.*$'
    for i in range(num_benchmarks):
        baseline_file = baseline[i]
        herqules_file = herqules[i]
        baseline_name = re.search(benchmark_pattern, str(baseline_file)).group(1)
        herqules_name = re.search(benchmark_pattern, str(herqules_file)).group(1)
        assert baseline_name == herqules_name
        benchmark_name = baseline_name
        print('extracting benchmark:', benchmark_name)
        baseline_app_ipc = get_app_ipc(baseline_file)
        herqules_app_ipc = get_app_ipc(herqules_file)

        all_benchmark_name.append(benchmark_name)
        all_baseline_app_ipc.append(baseline_app_ipc)
        all_herqules_app_ipc.append(herqules_app_ipc)

    return all_benchmark_name, all_baseline_app_ipc, all_herqules_app_ipc



def autolabel(rects):
    """Attach a text label above each bar in *rects*, displaying its height."""
    for rect in rects:
        height = rect.get_height()
        ax.annotate('{:.2f}x'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(1, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', rotation=90, fontsize=9)



if __name__ == '__main__':

    res_cache = Path("res_cache.pkl")

    all_benchmark_name = []
    all_baseline_app_ipc = []
    all_herqules_app_ipc = []

    if not res_cache.exists():
        # Parse the stat files
        if (len(sys.argv[1:]) != 2):
            print('Usage: {} path/to/baseline /path/to/herqules'.format(sys.argv[0]))
            exit()
        else:
            print('Reading from .h5 files ...')
            all_benchmark_name, all_baseline_app_ipc, all_herqules_app_ipc = read_stat_files(sys.argv[1], sys.argv[2])

        # Write the results to pkl cache
        data = [all_benchmark_name, all_baseline_app_ipc, all_herqules_app_ipc]
        pickle_file = open(r'res_cache.pkl', 'wb')
        pickle.dump(data, pickle_file)
        pickle_file.close()
    else:
        # Read the results from pkl cache
        print('Reading from res_cache.pkl ...')
        pickle_file = open(r'res_cache.pkl', 'rb')
        data = pickle.load(pickle_file)
        pickle_file.close()
        all_benchmark_name = data[0]
        all_baseline_app_ipc = data[1]
        all_herqules_app_ipc = data[2]

    # Normalize IPCs
    for i in range(len(all_baseline_app_ipc)):
        all_herqules_app_ipc[i] /= all_baseline_app_ipc[i]
        all_baseline_app_ipc[i] = 1.0

    if PRINT_NUMBERS:
        print('Benchmark\tBaselineIPC\tHerQulesIPC')
        for i in range(len(all_benchmark_name)):
            print('{}\t{}\t{}'.format(all_benchmark_name[i], all_baseline_app_ipc[i], all_herqules_app_ipc[i]))

    if SHOW_GRAPH:
        x = np.arange(len(all_benchmark_name))  # the label locations
        width = 0.35  # the width of the bars
        fig, ax = plt.subplots()
        rects1 = ax.bar(x - width/2, all_baseline_app_ipc, width, label='Baseline')
        rects2 = ax.bar(x + width/2, all_herqules_app_ipc, width, label='Herqules')

        # Add some text for labels, title and custom x-axis tick labels, etc.
        ax.set_ylabel('Normalized Performance')
        ax.set_title('Performance Comparison of Baseline and CFI')
        ax.set_xticks(x)
        ax.set_xticklabels(all_benchmark_name)
        ax.legend()
        plt.xticks(rotation=90)
        autolabel(rects2)
        fig.tight_layout()
        plt.show()
        plt.savefig('graph.png')


