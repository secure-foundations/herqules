#!/usr/bin/env python3

import argparse
import collections
import os
import pandas
import six

OUTFILE="out.csv"

def get_info(file):
    ret = "-1"
    pid = "-1"

    if (os.path.exists(file)):
        with open(file, "r") as f:
            for line in f.readlines():
                if (line.startswith("exit ")):
                    ret = line[len("exit "):].strip()
                elif (line.startswith("pid ")):
                    pid = line[len("pid "):].strip()
    return (ret, pid)

def parse(root):
    dfs = []
    for subdirs, dirs, files in os.walk(root):
        if not subdirs.endswith("Output"):
            continue

        for f in files:
            if f.endswith(".perfstats"):
                fullpath = os.path.join(subdirs, f)
                print(fullpath)

                path = subdirs.split('/')
                suite = path[-3]
                benchmark = path[-2]
                ret, pid = get_info(fullpath[:-len(".perfstats")])

                try:
                    csv = pandas.read_csv(filepath_or_buffer=fullpath,skip_blank_lines=True,skiprows=1,header=None,index_col=2)
                    csv.drop(axis=1,labels=[1,3,4,5,6],inplace=True)
                    csv = csv.transpose()
                except pandas.errors.EmptyDataError:
                    csv = pandas.DataFrame([-1],columns=["task-clock"])

                csv.insert(0, "PID", pid)
                csv.insert(0, "Benchmark", benchmark)
                csv.insert(0, "Suite", suite)
                csv.insert(0, "Exit", ret)
                csv.rename_axis(None,axis=1,inplace=True)
                dfs.append(csv)

    outdata = pandas.concat(dfs,ignore_index=True,sort=False)
    outdata.sort_values(by=["Suite","Benchmark","PID"],inplace=True)
    outdata.to_csv(path_or_buf=os.path.join(root, OUTFILE),index=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    args = parser.parse_args()

    parse(args.directory)
