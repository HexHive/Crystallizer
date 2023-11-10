#!/bin/bash

# Copy over files pertaining to running the nogg mode of Crystallize


# Available cc, aw, vaadin
IMAGE="vaadin"
docker cp setup_jazzernogg.sh  crystallize_$IMAGE:/root/SeriFuzz/src/dynamic/
docker cp SeriFuzz_nogg.java crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
docker cp TrackStatistics.java crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
docker cp GadgetDB.java crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
docker cp LogCrash.java crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
docker cp log4j.properties crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
docker cp run_campaign.sh crystallize_$IMAGE:/root/SeriFuzz/src/dynamic
