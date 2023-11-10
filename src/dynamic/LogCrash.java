package com.example;

import java.io.*;
import org.apache.log4j.Logger;
import java.util.Scanner;
import java.util.*;
import java.nio.file.Paths;
import java.nio.file.Files;
import com.code_intelligence.jazzer.autofuzz.Meta;

public class LogCrash {

    private static final Logger LOGGER = Logger.getLogger(LogCrash.class);
    // public static String crashDir = "/root/SeriFuzz/jazzer_nogg/crashes/";
    public static String crashDir = "/root/SeriFuzz/jazzer/crashes/";
    public static Integer crashID = 0;
    // The list of paths for which we have already seen a path through the JDK
    public static Set<Integer> throughJDKPaths= new HashSet<Integer>();

    // Ensure that the crash dir has been created
    public static void makeCrashDir() {
        File directory = new File(crashDir);
        if (! directory.exists()) {
            directory.mkdir();
        }
    }

    public static void initJDKCrashedPaths() {
        LOGGER.debug("Initializing the list of paths for which we have already seen crashes through the JDK");
        try {
            List<String> crashedIDs = Files.readAllLines(Paths.get(crashDir + "_throughJDK"));
            if (crashedIDs.size() > 0) {
                for (String pathID: crashedIDs) {
                    throughJDKPaths.add(Integer.valueOf(pathID));
                }
            }
        } catch (IOException e) {
            LOGGER.debug("No crashed paths through JDK found as of yet, maybe being reinitialized");
        }
    }
    
    public static void flushJDKCrashedPaths() {
        try {
            LOGGER.debug("Log crashed Path ID through JDK");
            Writer wr = new FileWriter(crashDir + "_throughJDK"); 
            for (Integer pathID : throughJDKPaths) {
                wr.write(String.valueOf(pathID) + "\n");
            }
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not flush JDK crashed paths ");
            System.exit(1);
        }
    }

    // Write the next crash ID to be assigned in a file
    public static void initCrashID() {
        // If file does not exist 
        File tmpFile = new File(crashDir + "_currCrashID");
        if (! tmpFile.exists()) {
            try {
                LOGGER.debug("Initializing crash ID file.");
                Writer wr = new FileWriter(crashDir + "_currCrashID");
                wr.write(String.valueOf(LogCrash.crashID));
                wr.close();
            } catch (IOException e) {
                LOGGER.debug("Could not initialize crash ID file..exiting");
                System.exit(1);
            }
        } else {
            // Crash ID File already exists, reading it
            readCrashID();
        }
    }
    
    // Re-Initialize the potential sinks identified during the dynamic sink ID
    // phase if the file exists. This is necessary because during fork-based
    // mode the fuzzer might exit due to timeouts and we require to
    // re-initialize all the vulnerable sinks that were found
    public static void reinitVulnerableSinks() {
        File tmpFile = new File(crashDir + "potential_sinks");
        if (tmpFile.exists()) {
            LOGGER.debug("Reinit the vulnerable sinks that had been identified.");
            try {
                Scanner scanner = new Scanner(tmpFile);
                while (scanner.hasNextLine()) {
                    // The line is "Vulnerable Class:org.apache.commons.LazyMap" so we split on : and add
                    // just the class name
                    String line = scanner.nextLine();
                    if (line.startsWith("Vulnerable Class:")) {
                        String[] parts = line.split(":");
                        String clsName = parts[1].split(" ")[0];
                        DynamicSinkID.vulnerableClasses.add(clsName);
                    }
                }
                scanner.close();
            } catch (FileNotFoundException e) {
                LOGGER.debug("The file was not found");
                System.exit(1);
            }
        }
    }

    // Read the current crash ID to a file
    public static void readCrashID() {
        try {
            LOGGER.debug("Reading crash ID file.");
            File crashIDFile = new File(crashDir + "_currCrashID");
            Scanner scan = new Scanner(crashIDFile);
            // ArrayList<Integer> x = new ArrayList<Integer>();
            // while (scan.nextInt())
            LogCrash.crashID = scan.nextInt(); 
            LOGGER.debug("Current crash ID:" + LogCrash.crashID);
        } catch (IOException e) {
            LOGGER.info("Crash ID file could not be read...exiting");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void writeCrashID() {
        try {
            LOGGER.debug("Writing crash ID:" + LogCrash.crashID);
            Writer wr = new FileWriter(crashDir + "_currCrashID");
            wr.write(String.valueOf(LogCrash.crashID));
            wr.close();
        } catch (IOException e) {
            LOGGER.debug("Could not write to crash ID file..exiting");
            System.exit(1);
        }
    }

    // This stores the serialized payload onto disk when a sink gadget is triggered
    public static void storePayload(Object payload, boolean throughJDK) throws IOException {

        // Create a unique ID for the crash
        // 
        // If the payload control flow goes through uninstrumented jdk then we have observed a
        // case where we reached the sink without completely following through on the statically
        // observed path. In such cases we append such payloads with a _jdk prefix to identify
        // them
        FileOutputStream fos;
        long timestamp = TrackStatistics.getTimeForCrash();
        if (throughJDK) { 
            // Check first whether there already exists a logged crash for this path through the jdk
            if (throughJDKPaths.contains(Integer.valueOf(GadgetDB.currentPathID))) {
                LOGGER.debug("Crash through JDK already logged for:" + GadgetDB.currentPathID);
                return;
            }
            fos = new FileOutputStream(crashDir + String.valueOf(crashID) + "_" + String.valueOf(GadgetDB.currentPathID) +  "_jdk" + "_" + String.valueOf(timestamp));
            throughJDKPaths.add(GadgetDB.currentPathID);
            flushJDKCrashedPaths();
        }
        else {
            fos = new FileOutputStream(crashDir + String.valueOf(crashID) + "_" + String.valueOf(GadgetDB.currentPathID) + "_" + String.valueOf(timestamp));
        }
        ObjectOutputStream os = new ObjectOutputStream(fos);
        os.writeObject(payload);
        os.close();
        LogCrash.crashID += 1;
    }

    public static void logConstructionSteps() throws IOException {
        FileWriter fw = new FileWriter(LogCrash.crashDir + "construction_steps", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write("==Construction Steps==");
        bw.newLine();
        for (String step: Meta.constructionSteps) {
            bw.write(step);
            bw.newLine();
        }
        bw.close();
    }
}
