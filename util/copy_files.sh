#!/bin/bash

# This is a helper script to copy over relevant files for each phase to a provided outdir
set -x
set -e

# Utility script to copy to/from docker images
if [ ! "$#" -eq 2 ]; then
  echo "Usage: $0 <outdir> <mode>[sinkID]"
  exit 1
fi

OUTDIR=$1
MODE=$2


if [ "$MODE" = "sinkID" ]; then
    mkdir -p $OUTDIR/$MODE
    cp -p /root/SeriFuzz/jazzer/crashes/potential_sinks $OUTDIR/$MODE
    cp -p /root/SeriFuzz/jazzer/crashes/potential_sinks_processed $OUTDIR/$MODE
    cp -p /root/SeriFuzz/jazzer/crashes/potential_sinks_processed.serialized $OUTDIR/$MODE
    cp -p /root/SeriFuzz/jazzer/crashes/potential_sinks_exploitable $OUTDIR/$MODE
    cp -p /root/SeriFuzz/src/static/serifuzz.log $OUTDIR/$MODE/sinkID_log
fi

if [ "$MODE" = "concretization" ]; then
    mkdir -p $OUTDIR/$MODE
    cp -p /root/SeriFuzz/src/static/serifuzz.log $OUTDIR/$MODE/concretization_log
    cp -p /root/SeriFuzz/src/static/fnIDList.store $OUTDIR/$MODE/
    cp -p /root/SeriFuzz/src/static/gadgetDB.store $OUTDIR/$MODE/
    cp -pr /root/SeriFuzz/jazzer/crashes $OUTDIR/$MODE/
    cp -pr /root/SeriFuzz/jazzer/fuzzProgress.list $OUTDIR/$MODE/
    cp -p /root/SeriFuzz/jazzer/candidate_paths $OUTDIR/$MODE
fi

