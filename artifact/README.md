# Crystallizer-Artifact

This FSE'23 artifact for Crystallizer consists of three parts:

- Getting started and kick-the-tires instructions for basic sanity-checking of the framework
- Generate results presented in the paper using raw data from a prior run of the full evaluation done for Crystallizer.
- Re-run experiments from scratch and generate results. 

# Getting started 

## Setup docker 

- Install docker by following instructions for Ubuntu [here](https://docs.docker.com/engine/install/ubuntu/)
- After installation, configure Docker to make it run as a non-root user using instructions [here](https://docs.docker.com/engine/install/linux-postinstall/)

## Acquiring the image 

- Pull the docker image from docker-hub and run it
```
docker pull prashast94/crystallizer:artifact
```

## Kick-The-Tires (Sanity-check) [Estimated Time: 10 minutes]

We provide a set of sanity-check instructions that can be used to validate if the framework has been setup correctly.

- Deploy a short campaign to sanity-check that Crystallizer has been setup
  correctly end-to-end. The below scripts performs the following steps: 1)
Create intermediary gadget graph with no sinks marked, 2) Run the sink ID phase
for 1m and mark the candidate sinks post static filtering in the gadget graph,
and 3) Run the probabilistic concretization campaign logging paths that were
fully concretized. 
```
cd ./eval
./deploy_sanity_check.sh 1m 5m sanity_check
```

- To ensure that the above commands ran successfully, look into
`./eval/sanity_check/commons_collections_3.1/concretization`. You should see
a non empty directory and specifically inside `crashes` you should see a
non-empty directory of the list of paths that were concretized. The file names
can be interpreted as `<concretized_id>_<path_id>_<timeOfDiscovery>`.  So as an
example `0_1164_127` corresponds to the path with the index 1164 was found in
127 seconds. The index which this path corresponds to can be found in
`./eval/sanity_cehck/commons_collections_3.1/concretization/candidate_paths`. 

- Clean up the created docker image for subsequent steps using the following commands
```
docker stop crystallize_commons_collections3.1
docker rm crystallize_commons_collections3.1
```

# Reproduce results in the paper

- Un-tar the raw data for the results presented in the paper. The below command should create a directory `eval/data`. Note that these commands should be run *outside* the docker image on your host machine in a separate terminal.
```
cd ./eval
tar -xf data.tar.gz
```

## Library-based evaluation [Estimated Time: 2 minutes]

- Run the image with the raw data pertaining to our library-based data located in `./eval/data/lib_results` and mount it inside the image at `/root/SeriFuzz/results`. 
```
cd ./eval
docker run --security-opt seccomp=unconfined --name crystallize_libeval -v $PWD/data/lib_results/:/root/SeriFuzz/results -it prashast94/crystallizer:artifact /bin/bash
```

- Obtain the results for gadget graph creation stats (Table 2)
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m gadget_graph_stats
```

- Obtain the results for candidate chains that were explored, concretized, deemed to be interesting and found to be exploitable (Table 3)
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m categorize 
```

- Create the plot of time taken by Crystallizer to find the exploitable chains (Figure 3).
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m plot_confirmed 
```
    - The above script should create the visualization with the file name `figure_3.pdf` corresponding to the visualization in Figure 3 in `/root/SeriFuzz/results/`. From your host machine you can access and view it in `$HOME/Crystallizer_artifact/eval/data/lib_results/figure_3.pdf` 


- Obtain the novel chains found by Crystallizer apart from the ground truth chain and compare the unique classes present in both the ground truth chain and the novel chains (Table 4)
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m unique 
```

- Obtain the results for the ablation study comparing the efficacy of the gadget graph at finding gadget chains (Table 6) 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m ablation 
```

- Quantify the effectiveness of static filtering in identifying candidate sinks for exploration (Table 7)
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m sink_reduction
```

- After you're done recreating the results, please exit out of the docker image by typing `exit` in the terminal and then run the below commands to clean up image
```
docker stop crystallize_libeval
docker rm crystallize_libeval
```
## App-based case studies [Estimated Time: 15 minutes]

For our case studies on the three apps, we provide reproduction packages for the vulnerabilities found in Pulsar, Kafka, and Coherence.

- Run the docker image with the reproduction packages located at
`./eval/data/app_results` and mount them inside at `/root/SeriFuzz/results`.
Note, these instructions below need to be run in in a new terminal window in
your host and not inside the same terminal that you spawned for library-based
evaluation. Also, note the change in the `--name` argument from the previous 
```
cd ./eval
docker run --security-opt seccomp=unconfined --name crystallize_appeval -v $PWD/data/app_results/:/root/SeriFuzz/results -it prashast94/crystallizer:artifact /bin/bash
```

### Kafka 

We showcase a DoS attack being mounted on Kafka using a DoS chain that was
uncovered by Crystallizer in Apache Commons Collections 3.1. We provide a
`run_poc.sh` script to showcase first the benign behavior when no attack is
being mounted and then we show the attack being mounted using the serialized
payload. 

#### Benign

This showcases the scenario the benign scenario where no attack is being mounted. 
```
cd /root/SeriFuzz/results/Kafka
./run_poc.sh benign
```
- The intended behavior is that the test that is being run should pass successfully and you should see tests pass with the below message.
```
org.apache.kafka.connect.storage.FileOffsetBackingStoreTest > testGetSet PASSED
```
#### Attack 

To showcase the exploit being mounted using the commons collections library v3.1 run the script as:
```
cd /root/SeriFuzz/results/Kafka
./run_poc.sh 3.1
```
The intended behavior is that after the poc is run the application should run into a busy loop. Once you deploy the payload
the test will be stuck at the below step showcasing that the application has entered into a busy loop
```
> :connect:runtime:test > Executing test org.apache.kafka.connect.storage.FileOffsetBackingStoreTest
```
- Once you've observed this behavior, you can stop the testcase using `Ctrl-C`.

### Coherence

This is simple PoC showcasing the coherence vulnerability which is allowing for arbitrary method invocation
through reflection. The message `missing or inaccessible method` corresponds to evidence towards
an attacker-specified method being accessed. 

#### Run instructions
```
cd /root/SeriFuzz/results/Coherence
./run.sh
```

The above command will create a serialized payload for the vulnerability and
then trigger it through deserialization If the chain was executed successfully
then the deserilization should fail with the following message: `Missing or
inaccessible method: com.tangosol.util.extractor.ChainedExtractor.attacker()`.
This shows evidence of arbitrary method invocation and is the vulnerability
that is used to created a full-fledged RCE against Weblogic which uses
Coherence

```
./sanity_check.sh
```
The above command sanity checks that the chain known to be vulnerable can be
found from scratch. It creates the gadget graph from the sinks collected by
Crystallizer in an hour and then performs a constrained run focusing on
concretizing the known vulnerable chain. Once the chain gets concretized, the
process should exit. You should find the result of the concretization in
`/root/SeriFuzz/jazzer/crashes` which should have a file of the form of
`0_43326_*` where `43326` corresponds to the ID of the path of the known
vulnerable chain and `*` corresponds to the time taken to concretize this chain
which will vary run-to-run and machine-to-machine. Additionally, inside that
same folder, you should also see the steps Crystallizer took to concretize the
chain in `construction_steps` since we ran Crystallizer in its crash triage
mode.

### Pulsar

We showcase a RCE bug that can be exploited in Pulsar using a
deserialization-based attack uncovered by Crystallizer in Apache Commons
Collections library. We provide a `run_poc.sh` script to showcase attacks on
Apache Pulsar v2.2.0.

#### Run instructions 

To showcase the exploit being mounted on Apache Pulsar v2.2.0 run the script as:
```
cd /root/SeriFuzz/results/Pulsar
./run_poc.sh 2.2.0
```
To validate that the RCE attack was successful, you can check that there is a
file by the name of `attacked` created inside `pulsar-functions/api-java` which
is what we have designed the current payload to perform as evidence of remote
code execution.

Note that you may see some build failures, this is expected behavior since the
deserialized object which is our payload is different from the expected object
during deserialization but the important thing is that the attack happens
during the deserialization phase itself (evident from the attacker-created
file) and not during the casting phase.

- After you're done recreating the results for the app eval, please exit out of the docker image by typing `exit` in the terminal and then run the below commands to clean up image
```
docker stop crystallize_appeval
docker rm crystallize_appeval
```
# Run experiments from scratch

In this section, we provide instructions for how to run the experiments from
scratch. We first provide a shorter version of the experiments that are meant
to give an approximation of the results presented in the paper and then we
provide instructions on how to run our full library-based evaluation from
scratch as done in the paper. 

Note that the below evaluation deploys campaigns for all the seven
libraries in our dataset pinned to a single core respectively so please have at
least 7 cores at your disposal before running the below set of commands.

## Limited Evaluation [Estimated time: 2.5 hours]

- The limited evaluation is designed to be run for 70 minutes (10 min for sink identification and 60 minutes for probabilistic concretization). The below command will deploy concretization campaigns for all the seven libraries using the previously specified configuration and store the raw results in `./eval/limited` 
```
cd ./eval
./deploy_image.sh 10m 2h limited 
```

- After the duration of the limited evaluation has elapsed (we recommend waiting at least 20 minutes more to take into account project compilation time and timeout put between jobs), first check that all the campaigns have ended by running the below command and seeing if the output is `7` which is the number of libraries we are testing.
```
cd ./eval/limited
find . -name "concretization" -type d | wc -l
```

### Result aggregation

- Once the campaigns are finished, you can start using our data aggregation scripts following the below set of commands similar to what we did when reproducing results presented in the paper. Note that the numbers may be a bit different due to the limited time budget for the evaluation as compared to the full-fledged one as well as some amount of non-determinism associated with performing path concretization probabilistically. 

- Run the image with the raw data pertaining to our library-based data located in `./eval/limited` and mount it inside the image at `/root/SeriFuzz/results`. 
```
cd ./eval
docker run --security-opt seccomp=unconfined --name crystallize_limited -v $PWD/limited:root/SeriFuzz/results -it prashast94/crystallizer:artifact /bin/bash
```

- Obtain the results for gadget graph creation stats 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m gadget_graph_stats
```

- Obtain the results for candidate chains that were explored, concretized, deemed to be interesting and found to be exploitable (Table 3)
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m categorize 
```

- Obtain the novel chains found by Crystallizer apart from the ground truth chain and compare the unique classes present in both the ground truth chain and the novel chains 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m unique 
```
- Create the plot of time taken by Crystallizer to find the exploitable chains.
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m plot_confirmed 
```
    - The above script should create the visualization of time taken to uncover the exploitable chains. From your host machine you can access and view it in `$HOME/Crystallizer_artifact/eval/data/limited/figure_3.pdf` 

- Quantify the effectiveness of static filtering in identifying candidate sinks for exploration 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m sink_reduction
```

- After you're done recreating the results for the limited eval, please exit out of the docker image by typing `exit` in the terminal and then run the below commands to clean up image
```
docker stop crystallize_limited
docker rm crystallize_limited
```

- Clean up the other docker images that were created as part of the limited eval using the below utility script.
```
cd ./util
./clean_images.sh
```

## Full Evaluation [Estimated Time: 25 hours]

- The full evaluation is designed to be run for 25 hours (1 hour for sink identification and 24 hours for probabilistic concretization). The below command will deploy concretization campaigns for all the seven libraries using the previously specified configuration and store the raw results in `./eval/full` 
```
cd ./eval
./deploy_image.sh 1h 24h full 
```

- After the duration of the limited evaluation has elapsed  first check that all the campaigns have ended by running the below command and seeing if the output is `7` which is the number of libraries we are testing.
```
cd ./eval/full
find . -name "concretization" -type d | wc -l
```

### Result aggregation

- Once the campaigns are finished, you can start using our data aggregation scripts following the below set of commands similar to what we did when reproducing results presented in the paper. 

- Run the image with the raw data pertaining to our library-based data located in `./eval/full` and mount it inside the image at `/root/SeriFuzz/results`. 
```
cd ./eval
docker run --security-opt seccomp=unconfined --name crystallize_full -v $PWD/full:root/SeriFuzz/results -it prashast94/crystallizer:artifact /bin/bash
```

- Obtain the results for gadget graph creation stats 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m gadget_graph_stats
```

- Obtain the results for candidate chains that were explored, concretized, deemed to be interesting and found to be exploitable 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m categorize 
```

- Obtain the novel chains found by Crystallizer apart from the ground truth chain and compare the unique classes present in both the ground truth chain and the novel chains 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m unique 
```
- Create the plot of time taken by Crystallizer to find the exploitable chains (Figure 3).
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m plot_confirmed 
```
    - The above script should create the visualization of time taken to uncover the exploitable chains. From your host machine you can access and view it in `$HOME/Crystallizer_artifact/eval/data/full/figure_3.pdf` 

- Quantify the effectiveness of static filtering in identifying candidate sinks for exploration 
```
cd /root/SeriFuzz/eval
python aggregate_data.py -c config_paper_results.json -m sink_reduction
```

- After you're done recreating the results for the limited eval, please exit out of the docker image by typing `exit` in the terminal and then run the below commands to clean up image
```
docker stop crystallize_full
docker rm crystallize_full
```

- Clean up the other docker images that were created as part of the limited eval using the below utility script.
```
cd ./util
./clean_images.sh
```
