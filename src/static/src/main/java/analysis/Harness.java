package analysis; 

import soot.*;
import soot.jimple.*;
import soot.options.Options;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;

import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.nio.file.*;
import java.nio.file.Files;
import org.apache.log4j.Logger;

public class Harness { 

    private static final Logger LOGGER = Logger.getLogger(Harness.class);
    private static final int MAXLENGTH = 100;

    // This harness creates object generator for each class that is:
    // - Reachable from the trigger gadgets
    // - Part of the whitelisted pattern. We made this whitelisted pattern
    // adjustment because when testing with clojure we saw that a lot of java
    // JDK classes were whitelisted which when fuzzed would trigger java OOM
    // errors for heap allocations. So for this variant we only focus on
    // whitelisting the trigger gadgets and the classes corresponding to the
    // jar file that we are targeting
    //
    // For each of these classes it only generates primitive data types and
    // passes null values for reference data types
    // public static void HarnessV1() { 
    //     //XXX: Change the whitelisted pattern based on whatever jar file you're
    //     //targeting and the entry point you're using
    //     LOGGER.warn("Make sure that the includeList corresponds to whatever jar file you're targeting to find deserialization gadgets");
    //     List<String> includeList = Arrays.asList("clojure.", "java.util.HashMap");

    //     // Dump all whitelisted reachable classes into a list
    //     Set<String> clsBank = new HashSet<String>();
    //     for (GadgetMethod gm: GadgetDB.reachableList) {
    //         // Iterate through whitelisted pattern and see if the class has any of those
    //         // whitelisted patterns
    //         String clsName = gm.getClassName();
    //         // clsBank.add("\"" + clsName + "\"");
    //         for (String pattern: includeList) {
    //             if (clsName.startsWith(pattern)) {
    //                 clsBank.add("\"" + clsName + "\"");
    //                 break;
    //             }
    //         }
    //     }
    //     String clsBankString = String.join(",", clsBank);
    //     String dataBank = String.format(
    //             "class DataBank {%n" +
    //             "    public static String[] clsBank = new String[]{%s};%n" +
    //             "    public static int limit = %d;%n" +
    //             "}",
    //             clsBankString, MAXLENGTH
    //             );

    //     // Initialize the serialized databank object
    //     try {
    //         Path srcPath = Paths.get(System.getProperty("user.dir"), "src", "main", "resources", "HarnessV1.tmp");
    //         Path dstPath = Paths.get(System.getProperty("user.dir"), "src", "main", "resources", "HarnessV1.java");
    //         Files.copy(srcPath, dstPath, StandardCopyOption.REPLACE_EXISTING);
    //         FileWriter fw = new FileWriter(dstPath.toString(), true);
    //         BufferedWriter bw = new BufferedWriter(fw);
    //         bw.write(dataBank);
    //         bw.newLine();
    //         bw.close();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
	// }
}
