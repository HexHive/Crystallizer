package analysis;

import org.joda.time.LocalTime;
import soot.*;
import soot.jimple.JimpleBody;
import soot.jimple.internal.JIfStmt;
import soot.options.Options;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;
// import soot.toolkits.graph.ClassicCompleteUnitGraph;
// import soot.toolkits.graph.UnitGraph;

import java.util.ArrayList;
import java.util.List;
import java.util.LinkedList;
import java.util.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.log4j.Logger;

public class BaseAnalysis {

    private static final Logger LOGGER = Logger.getLogger(BaseAnalysis.class);

    public static void main(String[] args) {

        LOGGER.info("Starting up static analysis...");
        // Sanity check the argument string to ensure the correct number of
        // argumetns have been passed
        assert args.length <= 3 : "Incorrect number of arguments passed. Expected usage <jarfile> <mode> <sinkIDFile>"; 
        String jarFile = args[0];
        String mode = args[1];
        String sourceDirectory = Paths.get(jarFile).getParent().toString();
        String sinksInfo = null;
        String serializedSinks = null;
        if (mode.equals("sinkID") || mode.equals("sinkIDWrite")) {
            LOGGER.info("Sink ID mode");
            sinksInfo = args[2];
            LOGGER.info("Checking file:" + sinksInfo);
            assert (Files.exists(Paths.get(sinksInfo)) == true) : "The provided sink ID file does not exist";
        } else if (mode.equals("graph") || mode.equals("initgraph")) {
            LOGGER.info("Gadget graph construction mode");
            if (args.length == 3) {
                serializedSinks = args[2];
                LOGGER.info("Passed serialized sink file:" + serializedSinks);
                assert (Files.exists(Paths.get(serializedSinks)) == true) : "The provided sink ID file does not exist";
            } 
        } else {
            LOGGER.info("Unknown mode detected [sinkID/graph]. Exiting.");
            System.exit(1);
        }
        LOGGER.info(String.format("Jar file:%s", jarFile));
        LOGGER.info(String.format("Source dir:%s", sourceDirectory));

        // Ensure that the files indeed exist
        assert (Files.exists(Paths.get(jarFile)) == true) : "The provided jar file does not exist";
        assert (jarFile.contains(".jar")) : "Malformed jar file name provided";

        // Load in Lib-specific rules pertaining to which classes are
        // instrumented and analyzed in case thats necessary based on the jar
        // file being loaded.  Right now lib specific rules exist for Rome and
        // Click and are housed in LibSpecificRules.java
        //
        // Get the jar file name and load in lib-specific rules as specified in LibSpecificRules.java
        String fileName = Paths.get(jarFile).toFile().getName();
        if (fileName.equals("commons-collections-3.1.jar")) {
            LOGGER.debug("Lib specific rules for ACC3.1 loaded in..");
            LibAnalysis.libRules = new ACC31Rules();
        } else if (fileName.equals("commons-collections4-4.0.jar")) {
            LOGGER.debug("Lib specific rules for ACC4.0 loaded in..");
            LibAnalysis.libRules = new ACC40Rules();
        } else if (fileName.equals("aspectjweaver.jar")) {
            LOGGER.debug("Lib specific rules for aspectjweaver loaded in..");
            LibAnalysis.libRules = new AspectjweaverRules();
        } else if (fileName.equals("bsh-2.0b5.jar")) {
            LOGGER.debug("Lib specific rules for beanshell loaded in..");
            LibAnalysis.libRules = new BeanshellRules();
        } else if (fileName.equals("commons_beanutils.jar")) {
            LOGGER.debug("Lib specific rules for beanutils loaded in..");
            LibAnalysis.libRules = new BeanutilsRules();
        } else if (fileName.equals("click-withdeps-2.3.0.jar")) {
            LOGGER.debug("Lib specific rules for Click loaded in..");
            LibAnalysis.libRules = new ClickRules();
        } else if (fileName.equals("groovy-2.3.9.jar")) {
            LOGGER.debug("Lib specific rules for groovy loaded in..");
            LibAnalysis.libRules = new GroovyRules();
        } else if (fileName.equals("rome-1.0.jar")) {
            LOGGER.debug("Lib specific rules for Rome loaded in..");
            LibAnalysis.libRules = new RomeRules();
        } else if (fileName.equals("vaadin1.jar")) {
            LOGGER.debug("Lib specific rules for vaadin loaded in..");
            LibAnalysis.libRules = new VaadinRules();
        } else if (fileName.equals("coherence.jar")) {
            LOGGER.debug("Lib specific rules for coherence loaded in..");
            LibAnalysis.libRules = new CoherenceRules();
        } else {
            LOGGER.debug("No matching rules found for a library, loading in default rules");
            LibAnalysis.libRules = new DefaultRules();
        }

        // Initial graph being generated that has no sinks specified.
        if (mode.equals("initgraph")) {
            GadgetDB gadgetDBObj = new GadgetDB();
            LibAnalysis libClass = new LibAnalysis(jarFile, sourceDirectory, gadgetDBObj);
            libClass.setupSoot();
            libClass.runAnalysis();
        } else if (mode.equals("graph")) {
            long start = System.currentTimeMillis(); 
            GadgetDB gadgetDBObj = new GadgetDB();
            LibAnalysis libClass = new LibAnalysis(jarFile, sourceDirectory, gadgetDBObj);
            if (serializedSinks != null) {
                LibAnalysis.readMapSinks(serializedSinks);
            } else {
                LOGGER.debug("Using manually specified sinks in createMapSinks");
                LibAnalysis.createMapSinks();
            }
            libClass.setupSoot();
            libClass.runAnalysis();
            long end = System.currentTimeMillis(); 
            float sec = (end - start) / 1000F;
            LOGGER.info(String.format("Gadget graph creation time:%.0f seconds", sec));
        } else if (mode.equals("sinkID")) {
            //
            // Sink ID identification for RCE/DoS (requires a store to be present)
            // String jarFile = "/root/SeriFuzz/targets/commons_collections/commons-collections-3.1.jar";
            // String sourceDirectory = "/root/SeriFuzz/targets/commons_collections";
            // String sinksInfo = "/root/SeriFuzz/eval/raw_data/sp22/sinkID/potential_sinks";
            // String sinksInfo = "/root/SeriFuzz/jazzer/crashes/potential_sinks";
            SinkAnalysis sinkClass = new SinkAnalysis(jarFile, sourceDirectory, sinksInfo);
            sinkClass.setupSoot();
            sinkClass.readGraph();
            sinkClass.preProcess();
            sinkClass.runAnalysis();
            sinkClass.dumpProcessedSinks();
            sinkClass.dumpSerializedSinks();
            sinkClass.dumpExploitableSinks();
            sinkClass.dumpRelevantStats();
        } else if (mode.equals("sinkIDWrite")) {

            // Sink ID identification for arbitrary writes (the sinks info file is
            // just used to identify the file prefix where the statically
            // identified sinks will be placed)
            // String sinksInfo = "/root/SeriFuzz/jazzer/crashes/potential_sinks";
            SinkAnalysis sinkClass = new SinkAnalysis(jarFile, sourceDirectory, sinksInfo);
            sinkClass.setupSoot();
            sinkClass.readGraph();
            sinkClass.runWriteAnalysis();
            sinkClass.dumpProcessedSinks();
        } 
        // String clsName = "VulnObj_1";
        // String methodName = "readObject";
        // // String methodName = "";
        // String sourceDirectory = "/root/SeriFuzz/test/synthetic_3";
        // ClassAnalysis objClass = new ClassAnalysis(clsName, methodName, sourceDirectory);
        // objClass.setupSoot();
        // objClass.runAnalysis();
    }
}
