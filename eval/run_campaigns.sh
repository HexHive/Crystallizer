#!/bin/bash

# Helper script to sequentially perform all the Crystallizer steps for a given target library
# Usage ./run_campaigns.sh commons_collections3.1 1 1m 1m

JARFILE=$1 # The library which is to be tested
SINKID_TIMEOUT=$2 # The amount of time for which the sink identification phase is to be run
CONCRETIZATION_TIMEOUT=$3 # The amount of time for which the probabilistic concretization phase is to be run

source /etc/profile.d/gradle.sh

LIBNAME=$(dirname "$JARFILE")
echo $LIBNAME

# Create the intermediate gadget graph (with no sinks marked)
cd /root/SeriFuzz/src/static
# rm -f *.store serifuzz.log* && gradle run --args="/root/SeriFuzz/targets/$LIB_NAME/$JARFILE initgraph"
rm -f *.store serifuzz.log* && gradle run --args="$TARGET initgraph"

# Perform the dynamic candidate sink identification
cd /root/SeriFuzz/src/dynamic
timeout $SINKID_TIMEOUT ./run_campaign.sh $CPU_CORE SinkID $LIB_NAME

# From the set of identified candidate sinks perform static filtering to cut down potential false positive sinks
cd /root/SeriFuzz/src/static
rm -f serifuzz.log* && gradle run --args="/root/SeriFuzz/targets/$LIB_NAME/$JARFILE sinkID /root/SeriFuzz/jazzer/crashes/potential_sinks"

# Collect the results from the sink ID and put them into the result dir
cd /root/SeriFuzz/util
./copy_files.sh /root/SeriFuzz/results sinkID 

# Generate the final gadget graph (with the sinks marked)
cd /root/SeriFuzz/src/static
rm -f *.store serifuzz.log* && gradle run --args="/root/SeriFuzz/targets/$LIB_NAME/$JARFILE graph /root/SeriFuzz/jazzer/crashes/potential_sinks_processed.serialized"

# Ensure logging is turned on
cp /root/SeriFuzz/src/dynamic/log4j_verbose.properties /root/SeriFuzz/src/dynamic/log4j.properties
# Get the path list
cd /root/SeriFuzz/src/dynamic
./get_paths.sh

# Ensure logging is turned off before running concretization campaign 
cp /root/SeriFuzz/src/dynamic/log4j_nolog.properties /root/SeriFuzz/src/dynamic/log4j.properties

# Run the probabilistic concretization campaign
cd /root/SeriFuzz/src/dynamic
timeout $CONCRETIZATION_TIMEOUT ./run_campaign.sh $CPU_CORE Fuzz $LIB_NAME

# Collect the results from concretization and put it into the result dir
cd /root/SeriFuzz/util
./copy_files.sh /root/SeriFuzz/results concretization 
