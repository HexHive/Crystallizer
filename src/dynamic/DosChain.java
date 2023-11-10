package com.example;

import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.log4j.Logger;
import java.util.concurrent.ThreadLocalRandom;
import java.time.Instant;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;

import analysis.GadgetVertexSerializable;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.*;

class DosChain {

    // The DosChain discovery methodology is as follows:
    // - Pick a random reachable gadget as the sink, find all paths to it up to an upper-bound length from specified sources 
    // - Iterate through each of these paths and try to concretize them
    // - See if upon deserialization a DoS bug is triggered
    // - If it is triggered, log the chain as vulnerable to DoS
    //
    private static final Logger LOGGER = Logger.getLogger(DosChain.class);
    // public static Object[] reachableNodes = createArray();
    // public static Object[] createArray() { 
    //     List<GadgetVertexSerializable> reachableNodes = GadgetDB.findReachable();
    //     return reachableNodes.toArray();
    // }

    // public static AllDirectedPaths<GadgetVertexSerializable, DefaultEdge> allPaths = new AllDirectedPaths<>(GadgetDB.gadgetDBGraph);

    // XXX: We are not caching the directed paths for all sinks but are just
    // refinding them. Can probably make this opt if we see the discovery of
    // DoS bugs being slow
    public static boolean runAnalysis(FuzzedDataProvider data) {

        GraphPath<GadgetVertexSerializable, DefaultEdge> path = GadgetDB.pickPath();
        boolean didConcretize = GadgetDB.concretizePath(path, data);
         // If for even one of the nodes we were not able to create a concrete
         // object then we error out and try again
        if (!didConcretize) {
            Meta.localCache.clear();
            return false;
        }
        List<GadgetVertexSerializable> vertexList = path.getVertexList();
        GadgetVertexSerializable entryGadget = vertexList.get(0);
        Class<?> key = ObjectFactory.getClass(entryGadget.getClsName());
        Object payload = (Meta.localCache.get(key));

        Object finalPayload = null;
        try {
            finalPayload = SetupPayload.prepareTrigger(entryGadget.toString(), payload, path); 
        } catch (Exception e) {
            LOGGER.debug("Preparation of trigger gadget failed, exiting");
            e.printStackTrace();
            System.exit(1);
        }

        if (finalPayload == null) {
            LOGGER.debug("Empty payload generated which should not be possible");
            System.exit(1);
        }
        
        //TODO: Once we have identified if the concretized chain triggered a
        //DoS bug, we should look at the coverage file to see if all the
        //gadgets corresponding to the concretized chain were actually
        //observed, similar to something that we do in `TrackStatistics.java`.
        logChain(path);
        logInitDeserialization();
        SeriFuzz.entryPoint(finalPayload);
        Meta.localCache.clear();
        return true;
        //
        // // Pick a random reachable gadget as the sink
        // int choice = ThreadLocalRandom.current().nextInt(0, reachableNodes.length); 
        // GadgetVertexSerializable node = (GadgetVertexSerializable) reachableNodes[choice];
        // 
        // // Find all possible paths to it from the specified set of triggers
        // List<GraphPath<GadgetVertexSerializable, DefaultEdge>> paths = allPaths.getAllPaths(GadgetDB.triggerSet, Collections.singleton(node), true, SeriFuzz.maxPathLength); 
        // LOGGER.debug(String.format("Chosen sink:%s Number of paths:%d", node.toString(), paths.size()));

        // // Iterate through the paths and try to concretize them
        // for (GraphPath<GadgetVertexSerializable, DefaultEdge> path: paths) {

        //     boolean didConcretize = GadgetDB.concretizePath(path, data);
        //      // If for even one of the nodes we were not able to create a concrete
        //      // object then we error out and try again
        //     if (!didConcretize) {
        //         Meta.localCache.clear();
        //         continue;
        //     }
        //     List<GadgetVertexSerializable> vertexList = path.getVertexList();
        //     GadgetVertexSerializable entryGadget = vertexList.get(0);
        //     Class<?> key = ObjectFactory.getClass(entryGadget.getClsName());
        //     Object payload = (Meta.localCache.get(key));

        //     Object finalPayload = null;
        //     try {
        //         finalPayload = SetupPayload.prepareTrigger(payload); 
        //     } catch (Exception e) {
        //         LOGGER.debug("Preparation of trigger gadget failed, exiting");
        //         e.printStackTrace();
        //         System.exit(1);
        //     }

        //     if (finalPayload == null) {
        //         LOGGER.debug("Empty payload generated which should not be possible");
        //         System.exit(1);
        //     }
        //     
        //     logChain(path);
        //     logInitDeserialization();
        //     SeriFuzz.entryPoint(finalPayload);
        //     Meta.localCache.clear();
        // }

        // return true;
        //
        // Pick a specific node as the sink
        // GadgetVertexSerializable node = null;
        // int i;
        // for (i = 0; i < reachableNodes.length; i++) {
        //     GadgetVertexSerializable temp = (GadgetVertexSerializable) reachableNodes[i];
        //     // if (temp.toString().equals("<org.apache.commons.collections.functors.WhileClosure: void execute(java.lang.Object)>")) {
        //     if (temp.toString().equals("<org.apache.commons.collections.map.Flat3Map: java.lang.Object put(java.lang.Object,java.lang.Object)>")) {
        //         node = temp;
        //         break;
        //     }
        // }

        // Iterate through each path and print the vertices
        // List<GraphPath<GadgetVertexSerializable, DefaultEdge>> paths = allPaths.getAllPaths(GadgetDB.triggerSet, Collections.singleton(node), true, SeriFuzz.maxPathLength); 
        // int path_idx = 0;
        // for (GraphPath<GadgetVertexSerializable, DefaultEdge> path: paths) {
        //     List<GadgetVertexSerializable> vertexList = path.getVertexList();
        //     System.out.print("\n====\n");
        //     System.out.print(String.format("Idx:%d :: " , path_idx));
        //     for (GadgetVertexSerializable vertex : vertexList) {
        //         System.out.print("->" + vertex.toString());
        //     }
        //     System.out.print("\n====\n");
        //     path_idx += 1;
        // }
        // System.exit(1);

        // int pathIDX = 0;
        // GraphPath<GadgetVertexSerializable, DefaultEdge> path = paths.get(pathIDX);
        // boolean didConcretize = GadgetDB.concretizePath(path, data);
        //  // If for even one of the nodes we were not able to create a concrete
        //  // object then we error out and try again
        // if (!didConcretize) {
        //     Meta.localCache.clear();
        //     return false;
        // }
        // List<GadgetVertexSerializable> vertexList = path.getVertexList();
        // GadgetVertexSerializable entryGadget = vertexList.get(0);
        // Class<?> key = ObjectFactory.getClass(entryGadget.getClsName());
        // Object payload = (Meta.localCache.get(key));

        // Object finalPayload = null;
        // try {
        //     finalPayload = SetupPayload.prepareTrigger(payload); 
        // } catch (Exception e) {
        //     LOGGER.debug("Preparation of trigger gadget failed, exiting");
        //     e.printStackTrace();
        //     System.exit(1);
        // }

        // if (finalPayload == null) {
        //     LOGGER.debug("Empty payload generated which should not be possible");
        //     System.exit(1);
        // }
        // 
        // logChain(path);
        // logInitDeserialization();
        // SeriFuzz.entryPoint(finalPayload);
        // Meta.localCache.clear();

        // return true;
    }

    // Logs the current chain being tested
    public static void logChain(GraphPath<GadgetVertexSerializable, DefaultEdge> path) {
        String pathDesc = "";
        List<GadgetVertexSerializable> vertexList = path.getVertexList();
        for (GadgetVertexSerializable vertex : vertexList) {
            pathDesc += ("->" + vertex.toString());
        }
        try {
            LOGGER.debug("Writing current path being tested");
            Writer wr = new FileWriter(LogCrash.crashDir + "_currPath");
            wr.write(pathDesc);
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not write to crash ID file..exiting");
            System.exit(1);
        }
    }

    // Logs the time in seconds since epoch when the deserialization was started 
    public static void logInitDeserialization() {
        try {
            LOGGER.debug("Logging the last seen coverage timestamp");
            Writer wr = new FileWriter(LogCrash.crashDir + "_beginDeserialization"); 
            Instant instant = Instant.now();
            wr.write(String.valueOf(instant.getEpochSecond()));
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not write to last seen cov timestamp file..exiting");
            System.exit(1);
        }
    }

}
