#!/bin/bash

# This script runs the fuzzing campaign infinitely in a single threaded mode
# with the purpose of exposing chains that can trigger DoS vulnerabilities

# FUZZER_DIR="/root/SeriFuzz/jazzer_nogg"
FUZZER_DIR="/root/SeriFuzz/jazzer"
LOGDIR="$FUZZER_DIR/crashes"
TIMEOUT=10
CPU_NUM=$1
cd $FUZZER_DIR

rm -f _initTimeStamp _covStallTime _overThreshold _lastSeenCovTime fuzzProgress.list serifuzz.log* test.txt crashes/* && bazel build //:jazzer_release && tar -xf bazel-bin/jazzer_release.tar.gz -C bazel-bin/ && bazel build //examples:examples 
echo "./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** --keep_going=50 -timeout=$TIMEOUT -rss_limit_mb=8096" 
CMD="taskset -c $CPU_NUM ./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:/root/SeriFuzz/src/static/sootOutput/out.jar --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** -timeout=$TIMEOUT -rss_limit_mb=8096" 
while true
do
    echo "$PWD"
    echo "Restarting $CMD"
    rm -f crash-* timeout-* Crash_* test.txt 
    $CMD 
    read -r start<"$LOGDIR/_beginDeserialization"
    end=`date +%s`
    runtime=$((end-start))
    
    # Store the uncovered DoS chain into a logfile
    if (( $runtime >= $TIMEOUT )); then
        HAS_CHAIN=false
        read -r chain<"$LOGDIR/_currPath"
        CHAINFILE="$LOGDIR/dos_chains"
        # If the file does not exist then we just cat the chain into the file
        if [ ! -f $CHAINFILE ]; then
            echo "The chain file has not been initialized yet, initializing it with the new chain"
            echo "$chain" > $CHAINFILE
            continue
        else
            # Iterate through the chain file and see if the vulnerable chain already exists. If so don't log it
            while IFS= read -r line
            do
                echo "Line:$line"
                echo "=="
                if [[ "$line" == "$chain" ]]; then
                    echo "Chain already found"
                    HAS_CHAIN=true
                    break
                fi
            done < "$CHAINFILE"
        fi

        if $HAS_CHAIN; then
            echo "The chain already exists, not logging it"
            continue
        else
            echo "The chain does not exist, logging it"
            echo "$chain" >> $CHAINFILE
        fi
    fi
    sleep 1
done
