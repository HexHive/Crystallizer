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
import org.apache.log4j.Logger;
import java.io.*;

public class LibAnalysis extends BaseAnalysis {

    private static final Logger LOGGER = Logger.getLogger(LibAnalysis.class);
    // Set some known default entry points
    public static List<String> entryPoints = new ArrayList<String>();
    // public static Map<String, List<String>> sinks =  createMapSinks();
    public static Map<String, List<String>> sinks = new HashMap<String, List<String>>();
    public static LibSpecificRules libRules; // Specifies lib specific rules
    // private static List<String> createMap() {
    //     List<String> result = new ArrayList<String>();
    //     // result.put("Example", "gadget");    
    //     // result.put("clojure.inspector.proxy$javax.swing.table.AbstractTableModel$ff19274a", "hashCode");    
    //     // result.add("toString");    
    //     result.add("hashCode");    
    //     // result.add("compare");    
    //     // result.add("invoke");    
    //     // result.put("org.codehaus.groovy.runtime.ConvertedClosure", "invokeCustom");    
    //     // result.put("com.vaadin.data.util.PropertysetItem", "toString");    
    //     // result.put("org.apache.commons.collections.keyvalue.TiedMapEntry", "hashCode");    
    //     // result.put("VulnObj_1", "readObject");    
    //     // result.put("java.util.HashMap", "readObject");    
    //     return result;
    // }

    // Read the sinks
    public static void readMapSinks(String serializedSinks) {
        try {
            FileInputStream fis=new FileInputStream(new File(serializedSinks));
            ObjectInputStream ois=new ObjectInputStream(fis);
            sinks = (HashMap<String, List<String>>)ois.readObject(); 
            for (Map.Entry<String, List<String>> entry: sinks.entrySet()) {
                LOGGER.debug("Tagged sink:" + entry);
            }
            ois.close();
            fis.close();
        } catch(IOException | ClassNotFoundException e) {
            LOGGER.info("Could not read serialized sinks from:" + serializedSinks); 
            System.exit(1);
        }
        // System.exit(1);
    }

    public static void createMapSinks() {
	    // sinks.put("org.apache.click.control.Column", new ArrayList<String>(Arrays.asList("getProperty")));
	    sinks.put("com.sun.syndication.feed.impl.ToStringBean", new ArrayList<String>(Arrays.asList("toString")));
	    // result.put("org.apache.commons.collections.functors.InvokerTransformer", new ArrayList<String>(Arrays.asList("transform")));
	    // result.put("org.apache.commons.collections4.functors.InvokerTransformer", new ArrayList<String>(Arrays.asList("transform")));
	    // result.put("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap", new ArrayList<String>(Arrays.asList("put")));
	    // result.put("org.apache.commons.beanutils.BeanComparator", new ArrayList<String>(Arrays.asList("compare")));
    }

    public static List<String> excludeList = Arrays.asList("jdk.", "java.", "javax.",
        "sun.", "sunw.", "com.sun.", "com.ibm.","com.apple.","apple.awt.", "org.xml", "org.w3c");

    String jarFile; // Specify the jar file being analyzed
    String sourceDirectory; // Specify the source code directory of the analyzed target 
    GadgetDB gadgetDBObj; // Class dependency graph for the jar file


    public LibAnalysis(String jarFile, String sourceDirectory, GadgetDB gadgetDBObj) {
        this.jarFile = jarFile;
        this.sourceDirectory = sourceDirectory;
        this.gadgetDBObj = gadgetDBObj;
    }
    
    public void setupSoot() {
        G.reset();
        Options.v().set_prepend_classpath(true); //-pp
        Options.v().set_whole_program(true); //-w
        Options.v().set_allow_phantom_refs(true);
        List<String> processdirs = new ArrayList<>();
        PackManager.v().getPack("jtp").add(new Transform("jtp.HitCountInstrumenter", HitCountInstrumenter.v()));
        // Options.v().set_output_format(Options.output_format_jimple);
        processdirs.add(jarFile);
        Options.v().set_process_dir(processdirs);
        Options.v().set_soot_classpath(sourceDirectory);
        Options.v().set_output_jar(true); // Creates the output jar file with instrumented code
        Scene.v().loadNecessaryClasses();
        LibAnalysis.libRules.forceSetApplicationClasses();
        try {
            LibAnalysis.libRules.initializeEntryPoints();
        } catch (Exception e) {
            e.printStackTrace();
        }
        // excludeJDKLib();
    }

    // In the case of rome lib, the classes being analyzed and instrumented
    // belong to com.sun.syndicate.* which is part of the JDK hence its ignore
    // by default by Soot during running its instrumentation passes. Therefore,
    // even though we could perform our gadget graph creation analysis, the
    // instrumented jar file would not be created. To address this we need to
    // explicitly set each of the classes with this prefix as an application
    // class
    // public static void forceSetApplicationClasses() {
    //     for (SootClass sc : Scene.v().getClasses()) {
    //         if (sc.getName().startsWith("com.sun.syndication")) {
    //         // if (sc.getName().startsWith("javax.")) {
    //             sc.setApplicationClass();
    //         } 
    //     }
    // }

    public static void excludeJDKLib() {
        Options.v().set_exclude(excludeList);
        Options.v().set_no_bodies_for_excluded(true);
    }

    public void runAnalysis() {
        callGraphAnalysis();
        PackManager.v().writeOutput();
        // gadgetDBObj.getSpecificEdgesSoot("org.apache.commons.collections.map.AbstractMapDecorator", "equals");    
        // System.exit(1);
        buildUniverse();
        FunctionIDMap.sanityCheckIDs();
        FunctionIDMap.flushMap(); 
        // LOGGER.debug("Reading the flushed fnIDmap from disk and sanity-checking");
        // FunctionIDMap.readMap();
        gadgetDBObj.encodeGraphFlush();
        // LOGGER.debug("Reading the flushed gadgetDBGraph from disk and sanity-checking");
        // gadgetDBObj.readGraphSerializable();
        // 
        // Do the bookkeeping to identify the size of the gadget graph
        gadgetDBObj.findReachable();
        gadgetDBObj.countCallGraphNodesEdges();
        // gadgetDBObj.iterateAllEdges();
        // buildHarness();
    }

    // Does backwards analysis from the sink to identify all viable methods
    // that could be a part of a gadget chain 
    public void findViableNodes() {
        List<SootMethod> workList = new ArrayList<SootMethod>();
        List<SootMethod> viableNodes = new ArrayList<SootMethod>();
        for(Map.Entry<String, List<String>> sink: sinks.entrySet()) { 
            SootClass sc = Scene.v().getSootClass(sink.getKey());
            List<String> methodNames = sink.getValue();
            for (String methodName: methodNames) {
                SootMethod sm = sc.getMethodByName(methodName);
                workList.add(sm);
            }
        }
        while (! workList.isEmpty()) {
            SootMethod candidate = workList.remove(0);
            for(Iterator<Edge> it = GadgetDB.callGraph.edgesInto(candidate); it.hasNext(); ) {
                Edge edge = it.next();
                if (viableNodes.contains(candidate)) {
                    LOGGER.debug("Method:" + edge.src() + " invokes method:"+ edge.tgt() + ": This edge already seen");
                    continue;
                }
                LOGGER.debug("Method:" + edge.src() + " invokes method:"+ edge.tgt());
                viableNodes.add(edge.src());
                workList.add(edge.src());
            } 
        }
        LOGGER.info("Number of viable nodes:" + viableNodes.size());
    }

    // Create the harness that will drive the dynamic analysis engine using Jazzer
    // public void buildHarness() {
    //     LOGGER.info("Finding reachable ctions");
    //     gadgetDBObj.findReachable();
    //     LOGGER.info("Creating dynamic harness");
    //     Harness.HarnessV1();
    // }

    public void callGraphAnalysis() {
        List<SootMethod> entryPointsList = new ArrayList<SootMethod>();
        // Set the entry points for call graph construction
        for (SootClass sc : Scene.v().getClasses()) {
            boolean shouldSkip = false; 
            for (String excluded: excludeList) {
                if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("com.sun.syndication"))) {
                // if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("javax."))) {
                // if (sc.getName().startsWith(excluded)) {
                    LOGGER.debug("Denylisted class, skipping");
                    shouldSkip = true;
                    break;
                }
            }
            if (shouldSkip)
                continue;
            for (SootMethod sm: sc.getMethods()) {
                for (String entryPoint: entryPoints) {
                    if (sm.getName().equals(entryPoint)) {
                        // SootClass c = Scene.v().forceResolve(sc.getName(), SootClass.BODIES);
                        // c.setApplicationClass();
                        LOGGER.debug(String.format("Adding entry point:%s.%s", sc.getName(), sm.getName()));
                        entryPointsList.add(sm);
                    }
                }
            }
        }
        // SootClass c = Scene.v().forceResolve(entry.getKey(), SootClass.BODIES);
        // c.setApplicationClass();
        // SootMethod method = c.getMethodByName(entry.getValue());
        // entryPointsList.add(method);
        LOGGER.info("Entry points specified:" + entryPointsList.size());
        Scene.v().setEntryPoints(entryPointsList);
        PackManager.v().runPacks();
        GadgetDB.callGraph = Scene.v().getCallGraph();
    }

    public void buildUniverse() {
        for (SootClass sc : Scene.v().getClasses()) {
            boolean shouldSkip = false;
            LOGGER.debug("Class name: " + sc.getName());

            // Check if the class needs to be excluded from being put into the gadget graph
            if (LibAnalysis.libRules.excludeClass(sc.getName())) {
                LOGGER.debug("Denylisted class, skipping");
                continue;
            }
            // Filter out classes that belong to java. since Soot seemingly does not filter them
            // out during the callgraph generation 
            // for (String excluded: excludeList) {
            //     // XXX: We tried the below exclusion in 4 places where exclude list was used but seemingly the rome package is not
            //     // visible while performing instrumentation outputting an empty jar file
            //     // The second condition is to make a fine-grained filter that exlcudes all com.sun packages except
            //     // com.sun.syndicate which needs to be included as a part of the analysis for the ROME library
            //     if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("com.sun.syndication"))) {
            //     // if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("javax."))) {
            //     // if (sc.getName().startsWith(excluded)) {
            //     if (
            //         LOGGER.debug("Denylisted class, skipping");
            //         shouldSkip = true;
            //         break;
            //     }
            // }
            // if (shouldSkip)
            //     continue;

            if (GadgetID.isSerializable(sc)) {
                for (SootMethod method: sc.getMethods()) {
                    // Add all serializable methods as dependency graph vertices
                    LOGGER.debug("Creating vertex: " + method.getName()); 
                    GadgetMethod gmObj = new GadgetMethod(method);
                    LOGGER.debug("Adding vertex: " + method.getName()); 
                    gadgetDBObj.addVertex(gmObj);
                }
            }
            else {
                LOGGER.debug("Not serializable, skipping");
            }
        }
        LOGGER.info("Inferring edges..");
        gadgetDBObj.inferEdges();
        LOGGER.info("Number of vertices:" + (gadgetDBObj.gadgetDBGraph.vertexSet()).size());
        LOGGER.info("Number of edges:" + (gadgetDBObj.gadgetDBGraph.edgeSet()).size());
        LOGGER.info("Removing isolated vertices");
        gadgetDBObj.removeIsolatedNodes();

        // Enumerate the number of triggers and sinks
        for (GadgetVertex vertex: gadgetDBObj.gadgetDBGraph.vertexSet()) {
            if (vertex.node.type.equals("Trigger")) { 
                GadgetDB.num_triggers += 1;
            }
            if (vertex.node.type.equals("Sink")) {
                GadgetDB.num_sinks += 1;
            }
            if (vertex.node.type.equals("TriggerSink")) {
                GadgetDB.num_triggers += 1;
                GadgetDB.num_sinks += 1;
            }
        }

        LOGGER.info("Number of vertices:" + (gadgetDBObj.gadgetDBGraph.vertexSet()).size());
        LOGGER.info("Number of edges:" + (gadgetDBObj.gadgetDBGraph.edgeSet()).size());
        LOGGER.info("Number of triggers:" + GadgetDB.num_triggers);
        LOGGER.info("Number of sinks:" + GadgetDB.num_sinks);

        // LOGGER.info("Calculating paths");
        // for(Map.Entry<String, String> sink: sinks.entrySet()) { 
        //         SootClass sc_sink = Scene.v().getSootClass(sink.getKey());
        //         SootMethod sm_sink = sc_sink.getMethodByName(sink.getValue());
        //         gadgetDBObj.findConnectedNodes(sm_sink);
        // }
        // gadgetDBObj.renderGraph();
    }


}
