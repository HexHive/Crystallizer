#!/bin/bash


FUZZER_DIR="/root/SeriFuzz/jazzer"
LIB=$1
cd $FUZZER_DIR
rm -f crashes/potential_sinks
rm -f commons.txt tmp.txt cov.out fuzzProgress.list serifuzz.log* test.txt && bazel build //:jazzer_release && tar -xf bazel-bin/jazzer_release.tar.gz -C bazel-bin/ && bazel build //examples:examples 
# CMD="~/SeriFuzz/jazzer/bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:$LIB --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** --keep_going=50 -timeout=2 -rss_limit_mb=8096" 
echo "./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:$LIB --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** --keep_going=50 -timeout=2 -rss_limit_mb=8096" 
CMD="./bazel-bin/jazzer --cp=./bazel-bin/examples/SeriFuzz_target_deploy.jar:$LIB --target_class=com.example.SeriFuzz --instrumentation_excludes=org.jgrapht.**::org.apache.log4j.**::javassist.** --custom_hooks=com.example.RuntimeFuzzerHooks --custom_hook_excludes=javassist.** --keep_going=50 -timeout=2 -rss_limit_mb=8096" 
while true
do
    echo "$PWD"
    echo "Restarting $CMD"
    rm -f crash-* timeout-* Crash_* serifuzz.log* test.txt 
    $CMD 
    sleep 1
done
