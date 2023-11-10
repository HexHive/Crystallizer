#!/bin/bash

# This script runs the fuzzing campaign infinitely in a single threaded mode
# the reason we do this is because the experimental fork mode in jazzer seems
# to be extremely slow

# FUZZER_DIR="/root/SeriFuzz/jazzer_nogg"
FUZZER_DIR="/root/SeriFuzz/jazzer"
MODE_FILE="$FUZZER_DIR/_crystallizer_mode"
LIB_FILE="$FUZZER_DIR/_libname"
MODE=$1
LIB=$2
cd $FUZZER_DIR

rm -f _initTimeStamp _covStallTime _overThreshold _lastSeenCovTime fuzzProgress.list serifuzz.log* test.txt crashes/* && bazel build //:jazzer_release && tar -xf bazel-bin/jazzer_release.tar.gz -C bazel-bin/ && bazel build //examples:examples 

echo -n $MODE > $MODE_FILE
echo -n $LIB > $LIB_FILE 

echo "./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** -timeout=5 -rss_limit_mb=8096" 
CMD="./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --keep_going=5000 -timeout=60 -rss_limit_mb=8096" 
while true
do
    echo "$PWD"
    echo "Restarting $CMD"
    rm -f crash-* timeout-* Crash_* test.txt 
    $CMD 
    sleep 1
done
