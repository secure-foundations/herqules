#! /usr/bin/env python3

import h5py
import sys
from pathlib import Path
import numpy as np
import math
import re

import matplotlib
import matplotlib.pyplot as plt

# PRINT_NUMBERS = False
PRINT_NUMBERS = True

# SHOW_GRAPH = False
SHOW_GRAPH = True


def get_stat_value(stat_pointer, parameter, begin_index=0):
    # stat_pointer: e.g., core stats, l1d stats, etc.
    # parameter: str, e.g., 'cycles', 'instrs', etc.
    # begin_index: int, from which dump onwards we care about the results

    # This is an array of values with len() == core count, where every entry in
    # array corresponds to a particular core
    return np.array(stat_pointer[parameter][-1]) - np.array(stat_pointer[parameter][begin_index])



def get_total_number_of_cyles(stat_file):
    """
    Return the total number of cycles (no notion of warmup here)
    """
    stats = h5py.File(stat_file, 'r')
    stats = stats['stats']['root']
    core_name = 'c'
    core_stats = stats[core_name]
    total_cycles = get_stat_value(core_stats, 'cycles')

    return total_cycles[0]



def read_stat_files(path1, path2):
    stat_file_pattern = '**/zsim_*.h5'
    baseline = list(sorted(Path(path1).glob(stat_file_pattern)))
    herqules = list(sorted(Path(path2).glob(stat_file_pattern)))
    assert len(baseline) == len(herqules)
    num_benchmarks = len(baseline)

    all_benchmark_name = []
    all_baseline_whole_cycles = []
    all_herqules_whole_cycles = []

    benchmark_pattern = '^.*(\d\d\d\..*\.\d)\/.*$'
    for i in range(num_benchmarks):
        baseline_file = baseline[i]
        herqules_file = herqules[i]
        baseline_name = re.search(benchmark_pattern, str(baseline_file)).group(1)
        herqules_name = re.search(benchmark_pattern, str(herqules_file)).group(1)
        assert baseline_name == herqules_name, 'baseline_name=' + str(baseline_name) + ', herqules_name=' + str(herqules_name)
        benchmark_name = baseline_name
        print('extracting benchmark:', benchmark_name)
        if 'specrand' in baseline_name:
            print('Skipped', benchmark_name)
            continue
        baseline_whole_cycles = get_total_number_of_cyles(baseline_file)
        herqules_whole_cycles = get_total_number_of_cyles(herqules_file)

        all_benchmark_name.append(benchmark_name)
        all_baseline_whole_cycles.append(baseline_whole_cycles)
        all_herqules_whole_cycles.append(herqules_whole_cycles)

    return all_benchmark_name, all_baseline_whole_cycles, all_herqules_whole_cycles



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

    all_benchmark_name = []
    all_baseline_whole_cycles = []
    all_herqules_whole_cycles = []

    # Parse the stat files
    if (len(sys.argv[1:]) != 2):
        print('Usage: {} path/to/baseline /path/to/herqules'.format(sys.argv[0]))
        exit()

    print('Reading from .h5 files ...')
    all_benchmark_name, all_baseline_whole_cycles, all_herqules_whole_cycles = read_stat_files(sys.argv[1], sys.argv[2])

    # Normalize Performance
    all_baseline_performance = []
    all_herqules_performance = []
    for i in range(len(all_baseline_whole_cycles)):
        all_herqules_performance.append(all_baseline_whole_cycles[i] / all_herqules_whole_cycles[i])
        all_baseline_performance.append(1.0)


    if PRINT_NUMBERS:
        print('Benchmark\tBaselinePerformance\tHerqulesPerformance')
        for i in range(len(all_benchmark_name)):
            print('{}\t{}\t{}'.format(all_benchmark_name[i], all_baseline_performance[i], all_herqules_performance[i]))

    if SHOW_GRAPH:
        x = np.arange(len(all_benchmark_name))  # the label locations
        d = 0.8 * 1/2
        fig, ax = plt.subplots()
        rects1 = ax.bar(x - 1/2*d, all_baseline_performance, d, label='Baseline')
        rects2 = ax.bar(x + 1/2*d, all_herqules_performance, d, label='Herqules')

        # Add some text for labels, title and custom x-axis tick labels, etc.
        ax.set_ylabel('Normalized Performance')
        ax.set_title('Performance Comparison of Baseline and HerQules')
        ax.set_xticks(x)
        ax.set_xticklabels(all_benchmark_name)
        ax.legend()
        plt.xticks(rotation=90)
        autolabel(rects2)
        fig.tight_layout()
        plt.show()
        plt.savefig('graph.png')


