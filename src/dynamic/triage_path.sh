#!/bin/bash

# This script gets the number of paths to be explored given a gadget graph.
# and outputs it to the file named `candidate_paths`

# FUZZER_DIR="/root/SeriFuzz/jazzer_nogg"
FUZZER_DIR="/root/SeriFuzz/jazzer"
MODE_FILE="$FUZZER_DIR/_crystallizer_mode"
PATH_FILE="$FUZZER_DIR/_pathID"
PATH_ID=$1
# File where the paths are to be output
cd $FUZZER_DIR

rm -f _initTimeStamp _covStallTime _overThreshold _lastSeenCovTime fuzzProgress.list serifuzz.log* test.txt crashes/* && bazel build //:jazzer_release && tar -xf bazel-bin/jazzer_release.tar.gz -C bazel-bin/ && bazel build //examples:examples 
echo -n "CrashTriage" > $MODE_FILE
echo -n $PATH_ID > $PATH_FILE
echo "./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** -timeout=5 -rss_limit_mb=8096" 
CMD="./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --keep_going=5000 -timeout=60 -rss_limit_mb=8096" 
$CMD 
