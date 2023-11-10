package com.example; 

// import clojure.*;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.*;

import analysis.GadgetVertexSerializable;
import analysis.GadgetMethodSerializable;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;


import java.io.*; 
import java.lang.reflect.Constructor;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

// import org.apache.logging.log4j.Logger;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;


public class SeriFuzz { 
    
    // private static final FluentLogger logger = FluentLogger.forEnclosingClass();
    private static final Logger LOGGER = Logger.getLogger(SeriFuzz.class);
    private static String logProperties = "/root/SeriFuzz/src/dynamic/log4j.properties";

    // This sinkID is used to identify is sink gadget is triggered
    public static List<String> sinkIDs = new ArrayList<String>();

    // This flag identifies if we are running the fuzzer in the dynamic sink identification mode
    public static boolean isSinkIDMode = false;
    // This flag identifiers if we are running the fuzzer in the crash triage mode
    public static boolean isCrashTriageMode = false;
    // This flag identifies if we are running the fuzzer to find DoS bugs
    public static boolean isDosMode = false;
    // This flag identifies if we are running the fuzzer to enumerate all candidate paths 
    public static boolean isPathEnumerationMode = false;
    // This flag identifies if we are running the fuzzer without the aid of the gadget graph
    public static boolean isNoGGMode = false;

    // Specify the threshold time we put in to get new cov before we deem that the campaign has stalled 
    public static long thresholdTime = 3600;

    // Specifies the maximum length of the chains that are to be found
    public static int maxPathLength = 5;

    public static boolean sinkTriggered;

    // In case CrashTriage mode is enabled, we use this variable to keep track
    // of which path is being triaged
    public static int triagePathID;

    public static void readMode() {

        // This control string identifies which mode the dynamic analysis component should be run in.
        // Available modes: SinkID, CrashTriage, Dos, PathEnumeration, NoGG, Fuzz
        // This string is read from a file named `_crystallizer_mode` created in the
        // directory pointed by TrackStatistics.storeDir
        String crystallizerMode = null;

        try {
            BufferedReader br = new BufferedReader(new FileReader(TrackStatistics.storeDir + "_crystallizer_mode"));
            crystallizerMode = br.readLine(); 
            if (crystallizerMode.equals("SinkID")) {
                LOGGER.info("Turning on sink ID mode");
		// Read in the library being analyzed
            	BufferedReader br1 = new BufferedReader(new FileReader(TrackStatistics.storeDir + "_libname"));
            	DynamicSinkID.targetLibrary = br1.readLine(); 
                isSinkIDMode = true;
            } else if (crystallizerMode.equals("CrashTriage")) {
                LOGGER.info("Turning on crash triage mode");
		Scanner scanner = new Scanner(new File(TrackStatistics.storeDir + "_pathID"));
		GadgetDB.currentPathID = scanner.nextInt();
		LOGGER.info("Path ID to be triaged:" + GadgetDB.currentPathID);
		// Read in the path ID that is to be triaged
                isCrashTriageMode = true;
            } else if (crystallizerMode.equals("Dos")) {
                LOGGER.info("Turning on DOS mode");
                isDosMode = true;
            } else if (crystallizerMode.equals("PathEnumeration")) {
                LOGGER.info("Turning on path enumeration mode");
                isPathEnumerationMode = true;
            } else if (crystallizerMode.equals("NoGG")) {
                LOGGER.info("Turning on nogg mode");
                isNoGGMode = true;
            } else if (crystallizerMode.equals("Fuzz")) { 
                LOGGER.info("No specialized modes turned on, performing regular fuzzing");
            } else {
                LOGGER.info(String.format("Unknown mode found %s...exiting", crystallizerMode));
                System.exit(1);
            }
        } catch (IOException e) {
            LOGGER.info("Could not read crystallizer mode initiailizer..exiting");
            System.exit(1);
        }
    }

    public static void fuzzerInitialize(String[] args) {
        
        PropertyConfigurator.configure(logProperties);
        // Read in the mode in which Crystallizer is to be run
        SeriFuzz.readMode();
        LogCrash.makeCrashDir();
        LogCrash.initJDKCrashedPaths();
        TrackStatistics.logInitTimeStamp();

        // ObjectFactory.populateClassCache();
        if (isSinkIDMode) {
            Meta.isSinkIDMode = true;
            LOGGER.debug("Reinitializing vulnerable sinks found");
            LogCrash.reinitVulnerableSinks();
            // We do this to force init the class so that reachable classes are
            // computed before the fuzz timeout is enforced
            LOGGER.debug(String.format("Number of unique classes:%d", DynamicSinkID.uniqueClasses.length));
            return;
        }

        if (isCrashTriageMode) {
            LOGGER.debug("Running the fuzzer in crash triage mode");
            Meta.isCrashTriageMode = true;
        }

        LogCrash.initCrashID();
        GadgetDB.tagSourcesAndSinks();
        // GadgetDB.findAllPaths(); 
        if (! isSinkIDMode) {
            GadgetDB.findAllPaths(); 
        }

        if (! isDosMode) {
            TrackStatistics.initProgressCounters();
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        if (Meta.isCrashTriageMode) {
            Meta.constructionSteps.clear();
        }

        if (isPathEnumerationMode) {
            // GadgetDB.showVertices();
            GadgetDB.printAllPaths();
            System.exit(1);
        }

        // Operating in the dynamic sink ID mode
        if (isSinkIDMode) {
            boolean didTest = DynamicSinkID.testPotentialSinks(data);
            return;
        }

        // Operating in DoS bug discovery mode 
        if (isDosMode) {
            DosChain.runAnalysis(data);
            return;
        }

        // makeHookActive = false;
        sinkTriggered = false;

       	Meta.localCache.clear();
        GraphPath<GadgetVertexSerializable, DefaultEdge> candidate = null;
	if (isCrashTriageMode) {
            candidate = GadgetDB.paths.get(GadgetDB.currentPathID); 
	} else {
            candidate = GadgetDB.pickPath();
	}
        // if (LOGGER.isDebugEnabled()) {
        //     String pathStr = GadgetDB.getStrPath(candidate);
        //     LOGGER.debug("Chosen Path:" + pathStr);
        //     LOGGER.debug("Chosen Path ID:" + GadgetDB.currentPathID);
        // }
        TrackStatistics.numVertices = candidate.getVertexList().size(); 

        // Check if we have already found a crash for the corresponding path. We do this by checking if the number of nodes
        // correctly deserialized for a path is equal to the number of vertices in the path. This would mean that we have concretized
        // the entire path successfully and have seen the gadgets being deserialized
        boolean hasCrashedBefore = TrackStatistics.hasCrashedBefore();
        if (hasCrashedBefore) {
            // LOGGER.debug(String.format("Path ID:%d has been crashed before, continuing.", GadgetDB.currentPathID));
            return;
        }

        // Reset counters that keep track of various levels of progress of fuzzer in concretizing a path
        TrackStatistics.resetProgressCounters();

        boolean didConcretize = false;
        if (isNoGGMode) 
            didConcretize = GadgetDB.concretizePathNoGG(candidate, data);
        else
            didConcretize = GadgetDB.concretizePath(candidate, data);

        // If for even one of the nodes we were not able to create a concrete
        // object then we error out and try again
        if (!didConcretize) {
            Meta.localCache.clear();
            return;
        }

        LOGGER.debug("==Deserializing payload==");

        // makeHookActive = true;
        //
        // We reset the coverage file since during path validation it may have been populated
        TrackStatistics.resetCoverageFile();

        // If everything worked as expected then the node corresponding to the
        // entry gadget should have the entire payload and that is the only
        // thing we need to serialize 
        List<GadgetVertexSerializable> vertexList = candidate.getVertexList();
        GadgetVertexSerializable entryGadget = vertexList.get(0);
        Class<?> key = ObjectFactory.getClass(entryGadget.getClsName());
        Object payload = (Meta.localCache.get(key));

        // Performing special handling for the trigger gadget if it exists
        // LOGGER.debug("Putting payload inside the trigger gadget");
        Object finalPayload = null;
        try {
            finalPayload = SetupPayload.prepareTrigger(entryGadget.toString(), payload, candidate); 
        } catch (Exception e) {
            // We continue because in the setup payload for trigger gadget compare there is a chance
            // that it is instantiated incorrectly since we probabilistically tr
			// e.printStackTrace();
	        return;
        }
		

        if (finalPayload == null) {
            LOGGER.debug("Empty payload generated which should not be possible");
            System.exit(1);
        }
        
        // LOGGER.debug(String.format("Final:%s\nInitial:%s" , payload.toString(), finalPayload.toString()));
        entryPoint(finalPayload);

        // Record the covered gadgets during deserialization
        TrackStatistics.recordCoverage(candidate);
        // TrackStatistics.showCoverage();
        TrackStatistics.writeProgressCounters();
        TrackStatistics.flushProgressCounters();
        TrackStatistics.printProgressCounters(false);
        long elapsedNewCovTime = TrackStatistics.getNewCovElapsedTime();
        if (elapsedNewCovTime > thresholdTime) { 
            // Touch a file to with the timestamp of the last seen new coverage
            // as the signal for when the campaign stalled
            LOGGER.debug(String.format("Campaign has stalled after not finding new cov for:%d", elapsedNewCovTime));
            TrackStatistics.logCoverageStallTimeStamp();
        } else {
            // LOGGER.debug(String.format("Time taken to uncover new coverage:%d", elapsedNewCovTime));
            TrackStatistics.sanityCheckThresholdTime();
        }

        // Check if crash occurred, if so store the payload
        if (SeriFuzz.sinkTriggered) {
            try {
                String pathStr = GadgetDB.getStrPath(candidate);
                LOGGER.debug(String.format("Crash detected for path:%s \n Crash ID is:%d", pathStr, LogCrash.crashID));
                if (TrackStatistics.correctDeserializations < TrackStatistics.numVertices) { 
                    LOGGER.debug("Partial path realized due to routing through jdk");
                    LogCrash.storePayload(payload, true);
                }
                else {
                    LOGGER.debug("Complete path realized");
                    LogCrash.storePayload(payload, false);
                    if (Meta.isCrashTriageMode) {
                        LogCrash.logConstructionSteps();
                        System.exit(1);
                    }
                }
                LogCrash.writeCrashID();
                // System.exit(1);
            } catch (IOException e) {
                LOGGER.debug("Payload storage failed");
            }
        }

        // System.exit(1);
        // Take the concretized objects from the local cache and create a serialized payload from it
    }

    public static void entryPoint(Object inputObj) {
        try { 
            // Create a serialized object
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(inputObj);
            oos.flush();
            oos.close();
            // We reset the coverage file here since serialization would trigger some gadgets
            // as well which we are not intererested in.
            // XXX: This can potentially be removed if we infer that these gadgets being recorded
            // is not that big of an issue
            TrackStatistics.resetCoverageFile();
            // Deserialize it
            ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object unserObj = (Object)ois.readObject();
            ois.close();
            // Debug mode where we just pass the ground truth payload from commons collections
            // to sanity-check that the gadget chain can indeed be activated
            // FileInputStream fis = new FileInputStream("payload_new.bin");
            // ObjectInputStream ois = new ObjectInputStream(fis);
            // Object unserObj = (Object)ois.readObject();
            // ois.close();
        // } catch (IOException | ClassNotFoundException | ClassCastException ignored) {
        } catch (Exception e) {
            // Debug utility to print where the deserialization is failing
            // e.printStackTrace();
        }
    }

}

