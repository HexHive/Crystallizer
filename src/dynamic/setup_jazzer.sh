#!/bin/bash


ROOT="/root/SeriFuzz/jazzer"

# This is from where the auxiliary data structures corresponding to the
# gadgetDB and the functionID map are retrieved
STORE="/root/SeriFuzz/src/static/src/main/java/analysis"

# Get the jazzer repo
if [ ! -d $ROOT ]; then
    git clone https://github.com/CodeIntelligenceTesting/jazzer $ROOT
    cd $ROOT && git checkout fe0d993 && cd -
fi

rm $ROOT/examples/BUILD.bazel
ln -s $PWD/BUILD.bazel $ROOT/examples/BUILD.bazel

rm $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/BUILD.bazel
ln -s $PWD/BUILD_autofuzz.bazel $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/BUILD.bazel

rm $ROOT/maven.bzl
ln -s $PWD/maven.bzl $ROOT/maven.bzl

rm $ROOT/sanitizers/sanitizers.bzl
ln -s $PWD/sanitizers.bzl $ROOT/sanitizers/sanitizers.bzl

rm $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/Meta.java
ln -s $PWD/Meta.java $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/Meta.java

rm -f $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/ClassFiles.java
ln -s $PWD/ClassFiles.java $ROOT/agent/src/main/java/com/code_intelligence/jazzer/autofuzz/ClassFiles.java

rm -f $ROOT/examples/src/main/java/com/example/SeriFuzz.java
ln -s $PWD/SeriFuzz.java $ROOT/examples/src/main/java/com/example/SeriFuzz.java

rm -f $ROOT/examples/src/main/java/com/example/GadgetMethodSerializable.java
ln -s $STORE/GadgetMethodSerializable.java $ROOT/examples/src/main/java/com/example/GadgetMethodSerializable.java

rm -f $ROOT/examples/src/main/java/com/example/GadgetVertexSerializable.java
ln -s $STORE/GadgetVertexSerializable.java $ROOT/examples/src/main/java/com/example/GadgetVertexSerializable.java

rm -f $ROOT/examples/src/main/java/com/example/SeriFuzz.java
ln -s $PWD/SeriFuzz.java $ROOT/examples/src/main/java/com/example/SeriFuzz.java

rm -f $ROOT/examples/src/main/java/com/example/GadgetDB.java
ln -s $PWD/GadgetDB.java $ROOT/examples/src/main/java/com/example/GadgetDB.java

rm -f $ROOT/examples/src/main/java/com/example/ObjectFactory.java
ln -s $PWD/ObjectFactory.java $ROOT/examples/src/main/java/com/example/ObjectFactory.java

rm -f $ROOT/examples/src/main/java/com/example/LogCrash.java
ln -s $PWD/LogCrash.java $ROOT/examples/src/main/java/com/example/LogCrash.java

rm -f $ROOT/examples/src/main/java/com/example/TrackStatistics.java
ln -s $PWD/TrackStatistics.java $ROOT/examples/src/main/java/com/example/TrackStatistics.java

rm -f $ROOT/examples/src/main/java/com/example/RuntimeFuzzerHooks.java
ln -s $PWD/RuntimeFuzzerHooks.java $ROOT/examples/src/main/java/com/example/RuntimeFuzzerHooks.java

rm -f $ROOT/examples/src/main/java/com/example/SetupPayload.java
ln -s $PWD/SetupPayload.java $ROOT/examples/src/main/java/com/example/SetupPayload.java

rm -f $ROOT/examples/src/main/java/com/example/DynamicSinkID.java
ln -s $PWD/DynamicSinkID.java $ROOT/examples/src/main/java/com/example/DynamicSinkID.java

rm -f $ROOT/examples/src/main/java/com/example/DosChain.java
ln -s $PWD/DosChain.java $ROOT/examples/src/main/java/com/example/DosChain.java

# Initialize jazzer
cd $ROOT
REPIN=1 bazel run @unpinned_maven//:pin 
rm -f _initTimeStamp _covStallTime _overThreshold _lastSeenCovTime fuzzProgress.list serifuzz.log* test.txt crashes/* && bazel build //:jazzer_release && tar -xf bazel-bin/jazzer_release.tar.gz -C bazel-bin/ && bazel build //examples:examples

