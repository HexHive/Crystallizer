package com.example;

import java.io.*;
import java.util.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.FileAlreadyExistsException;
import java.time.Instant;
import org.apache.log4j.Logger;
// import org.apache.logging.log4j.Logger;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;

import analysis.GadgetVertexSerializable;
import analysis.GadgetMethodSerializable;

public class TrackStatistics {

    private static final Logger LOGGER = Logger.getLogger(TrackStatistics.class);

    // static String storeDir = "/root/SeriFuzz/jazzer_nogg/";
    static String storeDir = "/root/SeriFuzz/jazzer/";

    // Data structure to hold the progression made by the fuzzer while trying to concretize paths
    // The data held is : [Length of path, number of nodes successfully instantiated, number of nodes successfully invoked, number of nodes sucessfully invoked during deserialization]
    // Since the paths found are always in the same order we can use the order in which the paths are found as an implicit index
    public static List<Integer[]> progressList = new ArrayList<>();
    
    // Stats maintained to quantify success of SeriFuzz at exploring the state space
    public static int numVertices = 0;
    public static int correctInstantiations = 0; // Total number of gadgets for which declaring class objects were created successfully

    public static int correctInvocations = 0; // Total number of gadgets which were correctly invoked using the constructed objects
    public static int correctDeserializations = 0; // Total number of gadgets which were successfully triggered during deserialization 

    public static List<String> idMap = readgadgetIDMap();
    public static List<String> readgadgetIDMap() {
        LOGGER.info("Reading the fnidmap from disk");
        try {
            FileInputStream fin = new FileInputStream(GadgetDB.rootPath + "fnIDList.store");
            ObjectInputStream oin = new ObjectInputStream(fin);
            idMap = (List<String>) oin.readObject();
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }

        // int idx = 0;
        // for (String gadgetID: idMap) { 
        //     LOGGER.debug(String.format("Idx:%d Gadget:%s" , idx, gadgetID));
        //     idx += 1;
        // }
        return idMap;
    }

    public static void resetCoverageFile() {
        LOGGER.debug("Resetting coverage file");
        File myObj = new File("test.txt");
        myObj.delete();
    }
    
    public static void initProgressCounters() {
        // See if the progress counter map has been initialized already by trying to read
        // it from disk
        try {
            File toRead = new File(storeDir + "fuzzProgress.list");
            FileInputStream fis = new FileInputStream(toRead);
            ObjectInputStream ois = new ObjectInputStream(fis);
            TrackStatistics.progressList = (List<Integer[]>)ois.readObject(); 
            ois.close();
            fis.close();
            LOGGER.info("The progress map already exists, reading it from disk");
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            LOGGER.info("The progress map does not exist, initializing it from scratch");
            for (GraphPath<GadgetVertexSerializable, DefaultEdge> path: GadgetDB.paths) {
                TrackStatistics.progressList.add(new Integer[] {path.getVertexList().size(), 0, 0, 0});
            }
            flushProgressCounters();
        }
    }

    public static void resetProgressCounters() {
        TrackStatistics.correctInstantiations = 0;
        TrackStatistics.correctInvocations = 0;
        TrackStatistics.correctDeserializations = 0;
    }

    public static boolean hasCrashedBefore() {
        Integer[] value = TrackStatistics.progressList.get(GadgetDB.currentPathID);
        if (value[0].equals(value[3]))
            return true;
        else
            return false;
    }

    public static void writeProgressCounters() {

        // Flag to identify if we have seen new coverage in the context of
        // either successfully instantiated gadgets or successfully
        // deserialized gadgets
        boolean newCovSeen = false;

        Integer[] value = TrackStatistics.progressList.get(GadgetDB.currentPathID);
        // Sanity-check to ensure that the path for which the value being updated is the same
        // as the one that was being read in. We do this by comparing the number of vertices along
        // the path which is not perfect but should signal obvious discrepancies
        assert value[0] == TrackStatistics.numVertices : "The number of vertices in the deserialized candidate and the one which is being updated are different. This means that our premise that the same path is going to be assigned the same ID while being found is incorrect. Please update."; 
        Integer readCorrectInstantiations = value[1];
        Integer readCorrectInvocations = value[2];
        Integer readCorrectDeserializations = value[3];
        // Overwrite only in the case the existing counters are greater than the values read in
        // The intuition behind this is to keep track of the best performance of the fuzzer for
        // each path
        if (readCorrectInstantiations < TrackStatistics.correctInstantiations) { 
            newCovSeen = true;
            value[1] = TrackStatistics.correctInstantiations;
        }
        if (readCorrectInvocations < TrackStatistics.correctInvocations)
            value[2] = TrackStatistics.correctInvocations;
        if (readCorrectDeserializations < TrackStatistics.correctDeserializations) {
            newCovSeen = true;
            value[3] = TrackStatistics.correctDeserializations;
        }

        // If we see new coverage then we update the last seen new cov timestamp
        if (newCovSeen) {
            TrackStatistics.logLastSeenTimeStamp();
        }
        TrackStatistics.progressList.set(GadgetDB.currentPathID, value);
    }

    public static void flushProgressCounters() {
        try { 
            File progressFile = new File(storeDir + "fuzzProgress.list");
            FileOutputStream fos = new FileOutputStream(progressFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(TrackStatistics.progressList);
            oos.flush();
            oos.close();
            fos.close();
        } catch (IOException e) {
            LOGGER.debug("Writing the progress map to disk failed, exiting");
            System.exit(1);
        }
    }

    // Print all the stats relevant to gadget state space exploration
    static void printProgressCounters(boolean printAll) {
        LOGGER.debug("==Progress counters==");
        if (printAll) {
            for (Integer[] value: TrackStatistics.progressList) {
                LOGGER.debug(String.format("Num Vertices:%d Instantiated:%d Invoked:%d Deserialized:%d", value[0], value[1], value[2], value[3])); 
            }
        } else {
            Integer[] value = TrackStatistics.progressList.get(GadgetDB.currentPathID);
            LOGGER.debug(String.format("Num Vertices:%d Instantiated:%d Invoked:%d Deserialized:%d", value[0], value[1], value[2], value[3])); 
        }
    }


    public static void recordCoverage(GraphPath<GadgetVertexSerializable, DefaultEdge> candidate) {
        try {
            String coveredStr = "";
            List<String> gadgetIDs = Files.readAllLines(Paths.get("test.txt"));
            Set<String> seenGadgets = new HashSet<String>();
            for (String gadgetId: gadgetIDs) {
                // Get the corresponding gadget name
                String methodName = idMap.get(Integer.valueOf(gadgetId));
                // It could happen that based on how the objects are created, we could see the
                // same gadget being executed more than once. Our current analysis only identifies
                // simple paths with non-repeating vertices. Therefore, during record keeping we check
                // if a particular gadget has been seen before, if so, we do not count it towards the number
                // of correct deserializations
                if (seenGadgets.contains(methodName))
                    continue;

                coveredStr += (methodName + " ");
                // Check if the triggered method corresponds to any of the nodes along the path
                // If so increment the correct deserialization counter
                for (GadgetVertexSerializable vertex : candidate.getVertexList()) {
                    if (methodName.equals(vertex.getQualifiedName())) {
                        seenGadgets.add(methodName);
                        TrackStatistics.correctDeserializations += 1;
                    }
                }

            }
            // Check if all vertices corresponding to the path were concretized, if so, the we turn on the flag that would
            // log this 
            if (TrackStatistics.numVertices == TrackStatistics.correctDeserializations) {
                SeriFuzz.sinkTriggered = true;
            }

            LOGGER.debug("Covered gadgets:" + coveredStr);
        } catch(IOException e) {
            LOGGER.debug("Coverage tracking failed, the deserialized payload did not execute");
            // System.exit(1);
        }
    }

    // Debug method to show the coverage hit during 
    public static void showCoverage() {
        try {
            List<String> gadgetIDs = Files.readAllLines(Paths.get("test.txt"));
            String coveredStr = "";
            for (String gadgetId: gadgetIDs) {
                // Get the corresponding gadget name
                String gadgetName = idMap.get(Integer.valueOf(gadgetId));
                coveredStr += (gadgetName + " ");
            }
            LOGGER.debug("Covered gadgets:" + coveredStr);
        } catch(IOException e) {
            LOGGER.debug("No coverage file exists");
            // System.exit(1);
        }
    }

    // Logs the time in seconds since epoch when the last new coverage was seen
    public static void logLastSeenTimeStamp() {
        try {
            LOGGER.debug("Logging the last seen coverage timestamp");
            Writer wr = new FileWriter(storeDir + "_lastSeenCovTime"); 
            Instant instant = Instant.now();
            wr.write(String.valueOf(instant.getEpochSecond()));
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not write to last seen cov timestamp file..exiting");
            System.exit(1);
        }
    }

    public static void logInitTimeStamp() {
        try {
            File tmpFile = new File (storeDir + "_initTimeStamp");
            // If the init timestamp already exists means the it has already
            // been initialized and just the fuzzer is starting off after a
            // crash 
            if (tmpFile.exists()) 
                return;
            LOGGER.debug("Logging the init timestamp");
            Writer wr = new FileWriter(storeDir + "_initTimeStamp"); 
            Instant instant = Instant.now();
            wr.write(String.valueOf(instant.getEpochSecond()));
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not write to last seen cov timestamp file..exiting");
            System.exit(1);
        }
    }

    // Copy over the last seen new coverage timestamp as the point where the fuzzer stalled
    // and did not see any new coverage
    public static void logCoverageStallTimeStamp() {
        LOGGER.debug("Logging the coverage stall timestamp");
        File srcFile = new File (storeDir + "_lastSeenCovTime");
        Path srcPath = srcFile.toPath();
        Path copied = Paths.get(storeDir + "_covStallTime");
        try {
            Files.copy(srcPath, copied);
        } catch (FileAlreadyExistsException e) {
            LOGGER.debug("File already exists, skipping overwriting it");
        } catch (IOException e) {
            LOGGER.debug("Copy over failed...exiting");
            System.exit(1);
        }
    }

    // We sanity check that when new coverage is uncovered it is not
    // after the threshold time. If it is the case we log the time taken
    // to uncover the new  
    public static void sanityCheckThresholdTime() {
        // We check if the file exists which flags if a campaign is stalled 
        File tmpFile = new File(storeDir + "_covStallTime"); 
        // If the file exists and we have reached here means that we have uncovered
        // a path after the threshold time. Log the time taken to reach this
        if (tmpFile.exists()) {
            try {
                LOGGER.debug("Logging elapsed time for finding new cov which was larger than specified threshold");

                Scanner scan = new Scanner(tmpFile);
                long lastSeen = scan.nextLong(); 

                Writer wr = new FileWriter(storeDir + "_overThreshold", true); 
                Instant instant = Instant.now();
                long elapsed_time = instant.getEpochSecond() - lastSeen;
                wr.write(String.valueOf(elapsed_time) + "\n");
                wr.close();
            } catch (IOException e) {
                LOGGER.debug("Could not sanity check..exiting");
                System.exit(1);
            }
        } else {
            // The coverage stall file does not exist which means we haven't uncovered coverage beyond the threshold time
            return;
        }
    }

    // This returns the amount of time elapsed since last new coverage was observed 
    public static long getNewCovElapsedTime() {
        // Get current time
        Instant instant = Instant.now();
        long currentTime = instant.getEpochSecond();
        long lastSeen = 0;
        // Get last seen new cov time
        try {
            File lastSeenTimeStamp = new File(storeDir + "_lastSeenCovTime");
            Scanner scan = new Scanner(lastSeenTimeStamp);
            lastSeen = scan.nextLong(); 
        } catch (IOException e) {
            LOGGER.debug("Could not write to last seen cov timestamp file..exiting");
            System.exit(1);
        }
        return (currentTime - lastSeen);
    }

    // This returns the time taken for the current crash to be observed 
    public static long getTimeForCrash() {
        // Get current time
        Instant instant = Instant.now();
        long currentTime = instant.getEpochSecond();
        long initTimeStamp = 0;
        // Get last seen new cov time
        try {
            File initTimeStampFile = new File(storeDir + "_initTimeStamp");
            Scanner scan = new Scanner(initTimeStampFile);
            initTimeStamp = scan.nextLong(); 
        } catch (IOException e) {
            LOGGER.debug("Could not read init timestamp file..exiting");
            System.exit(1);
        }
        return (currentTime - initTimeStamp);
    }
}
