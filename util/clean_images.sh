#!/bin/bash

# Utility script to help in cleaning all the docker images that were made
LIBS="commons_collections3.1 commons_collections4 aspectjweaver beanshell commons_beanutils groovy vaadin1"
for lib in $LIBS; do
docker stop crystallize_$lib
docker rm crystallize_$lib
done
