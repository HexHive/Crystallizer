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
- Once the above script finishes running, you can see which paths were concretized by running the command below. The below script generates a file `concretized_paths.json` file containing the ID's along with the paths that were concretized.
```
python concretized_paths.py --concretized_ids ~/SeriFuzz/results/concretization/crashes --paths ~/SeriFuzz/results/concretization/candidate_paths
``` 

- For a given concretized path, if you want to see what steps did Crystallizer take to create the concretized payload you can run the below command. Once the path gets successfully concretized, it creates `construction_steps` file inside `~/SeriFuzzz/jazzer/crashes` that details the steps taken by Crystallizer to concretize the chain.
```
cd /root/SeriFuzz/src/dynamic
./triage_path.sh <concretized_path_id>
```

## Testing a new library

When testing a new library the same commands as above can be run by just
pointing to the new library to be analyzed as shown below. We propose running
the sink identification for 1h and the probabilistic concretization module for
24h.
```
./run_campaigns.sh /root/SeriFuzz/targets/newlibrary/newlibrary.jar 1h 24h
```
- Anytime during the course of the probabilistic concretization you can run the below command to see which paths are concretized
```
python concretized_paths.py --concretized_ids ~/SeriFuzz/jazzer/crashes --paths ~/SeriFuzz/jazzer/candidate_paths
```

In addition, Crystallizer allows a user to fine-tune which trigger gadgets are
taken into consideration when performing its analysis and also customize which
classes are analyzed as part of dynamic sink identification.

- When testing a new library, the default trigger gadgets used are
  corresponding to `toString` entrypoints. However, these can be easily
  extended or modifed to consider other entry points corresponding. The current
  supported entrypoints are `compare, hashCode, and invoke`. You can use either
  or all by simply uncommenting the lines [here](https://github.com/HexHive/Crystallizer/blob/main/src/static/src/main/java/analysis/LibSpecificRules.java#L53-L55). The static analysis module
  has certain other customization that can be applied when creating the gadget
  graph which can be exposed by creating a subclass of the class [here](https://github.com/HexHive/Crystallizer/blob/main/src/static/src/main/java/analysis/LibSpecificRules.java#L13)

- During dynamic sink identification, the default behavior is to consider all
  classes and their corresponding methods as potential sink candidates for
  analysis. However, this can be fine-tuned to exclude certain classes from
  consideration by creating a denylist [here](https://github.com/HexHive/Crystallizer/blob/main/src/dynamic/DynamicSinkID.java#L109) 
