# Getting started 

## Setup docker 

- Install docker by following instructions for Ubuntu [here](https://docs.docker.com/engine/install/ubuntu/)
- After installation, configure Docker to make it run as a non-root user using instructions [here](https://docs.docker.com/engine/install/linux-postinstall/)

## Acquiring the image 

- Pull the docker image from docker-hub and run it
```
docker pull prashast94/crystallizer:latest
```

# Run instructions

We provide instructions on how to run with a sample library (commons-collections-3.1)

- Run the image and with the target and result directory mounted 
```
docker run --security-opt seccomp=unconfined --name crystallize_test -v $PWD/targets:/root/SeriFuzz/targets -v $PWD/results:/root/SeriFuzz/results -it prashast94/crystallizer:latest /bin/bash
```

- Deploy a campaign which runs the entire pipeline from gadget graph creation to probabilistic concretization end-to-end. 
```
# Scripts take three parameters: <absolute path to library file> <Time spent for dynamic sink ID> <Time spent for probabilistic concretization>

./run_campaigns.sh /root/SeriFuzz/targets/commons_collections3.1/commons-collections-3.1.jar 60 60
```
- Once the above script finishes running, you can see which paths were concretized by running the command below.
```
python concretized_paths.py --concretized_ids ~/SeriFuzz/results/concretization/crashes --paths ~/SeriFuzz/results/concretization/candidate_paths
``` 
    - The above script generates a file `concretized_paths.json` file containing the ID's along with the paths that were concretized.

- For a given concretized path, if you want to see what steps did Crystallizer take to create the concretized payload you can run the below command.
```
cd /root/SeriFuzz/src/dynamic
./triage_path.sh <concretized_path_id>
```
