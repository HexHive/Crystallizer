import argparse
import json
import re
import os
import pprint
from collections import defaultdict
from pathlib import Path

'''
This module prints the full paths corresponding to the path ID's that were concretized by Crystallizer
Usage: python concretized_paths.py -c ~/SeriFuzz/results/concretization/crashes -p ~/SeriFuzz/results/concretization/candidate_paths
'''
def main():
    parser = argparse.ArgumentParser(description="Specifies the concretized paths")
    parser.add_argument("-c", 
            "--concretized_ids", 
            dest = "concretized_ids",
            help = "Directory containing the concretized IDs", 
            required= True)
    parser.add_argument("-p",
            "--paths", 
            dest = "paths",
            help = "File containing all the candidate paths inferred from the library", 
            required= True)
    args = parser.parse_args()

    concretized_dir = args.concretized_ids
    paths = args.paths

    concretized_paths(concretized_dir, paths)


def concretized_paths(concretized_dir, paths_file):
    '''
    This function collects all the concretized paths by cross-referncing the path ID's
    with the path file
    '''

    lib_paths_timing = dict()
    lib_paths_name = dict()
    lib_paths_sizes = list()
    unique_classes_lib = list()
    # print (lib)
    reduced_paths = list()
    # Create a dictionary mapping [path_id -> sink]
    # sink_map = parse_paths(config["candidate_paths"][lib])
    sink_map = parse_paths(paths_file)
    files = [filename.as_posix() for filename in Path(concretized_dir).iterdir()]
    for testcase in files:
        filename = testcase.split("/")[-1]
        if (filename[0] != "_"):
            concretized_id = int(filename.split("_")[1])
            ttd = int(filename.split("_")[2])
            sink_name = sink_map[concretized_id][0]
            path = sink_map[concretized_id][1]
            gadgets = path.split("->")[1:]

            # Deduplicate paths with repeated nodes 
            reduced_path = []
            for gadget in gadgets:
                if len(reduced_path) == 0:
                    reduced_path.append(gadget)
                elif (reduced_path[-1] != gadget):
                    reduced_path.append(gadget)
            if reduced_path not in reduced_paths:
                reduced_paths.append(reduced_path)
            else:
                continue
            path = "->" + ("->".join(reduced_path))
            # lib_paths_timing[concretized_id] = ttd
            lib_paths_name[concretized_id] = sink_map[concretized_id][1]
            # lib_paths_sizes.append(len(gadgets))
            # unique_classes = set()
            # for gadget in gadgets:
            #     unique_classes.add(gadget.split(" ")[0][1:-1])
            # unique_classes_lib.append(len(unique_classes))

    with open("concretized_paths.json", "w+") as fd:
        out_results = {
                'lib_paths_name': lib_paths_name,
        }
        json.dump(out_results, fd)

def parse_paths(path_file):
    '''
    Parse the candidate_paths file to create map from path ID to the sink the corresponding path has 
    '''
    pattern = re.compile("Idx:([\d]+) :: ([\s\S]+)")
    sink_map = dict()
    with open(path_file, "r") as fd:
        lines = fd.readlines()
        for line in lines:
            if "Idx" in line:
                matched = pattern.match(line)
                if (matched):
                    path_idx, path = int(matched.group(1)), matched.group(2)
                    gadgets = path.split("->")[1:]
                    sink = gadgets[-1]
                    sink_map[path_idx] = [sink, path]
    return sink_map 






if __name__ == "__main__":
    main()
