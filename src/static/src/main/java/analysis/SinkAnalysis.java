package analysis;

import soot.*;
import soot.jimple.*;
import soot.options.Options;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;

import org.jgrapht.*;
import org.jgrapht.graph.*;

import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.apache.log4j.Logger;
import java.io.*;

public class SinkAnalysis extends BaseAnalysis {

    private static final Logger LOGGER = Logger.getLogger(SinkAnalysis.class);

    String jarFile; // Specify the jar file being analyzed
    String sourceDirectory; // Specify the source code directory of the analyzed target 
    String sinksInfo; // Specify the output file `potential_sinks` from sink ID phase of the dynamic analysis module
    // Map from potential sink class to the vulnerable instantiating argument
    Map<String, String> sinkArgs = new HashMap<String, String>();
    Set<String> exploitableSinks = new HashSet<String>();
    // Map from potential sink class to its corresponding reachable methods (gadgets)
    Map<String, List<String>> sinkMethods = new HashMap<String, List<String>>();
    // Map from processed sink class to their filtered reachable methods (gadgets)
    Map<String, List<String>> processedSinks = new HashMap<String, List<String>>();

    // Holds the initial sink set (used for quantifying sink set reduction)
    Set<String> initialSinkSet = new HashSet<String>();
    // Holds the final sink set (used for quantifying sink set reduction)
    Set<String> finalSinkSet = new HashSet<String>();

    public static Graph<GadgetVertexSerializable, DefaultEdge> gadgetDBGraph = new DefaultDirectedGraph<>(DefaultEdge.class);

    public static boolean foundRef = false;
    public static boolean foundWrite = false;

    public SinkAnalysis(String jarFile, String sourceDirectory, String sinksInfo) {
        this.jarFile = jarFile;
        this.sourceDirectory = sourceDirectory;
        this.sinksInfo = sinksInfo;
    }

    public void setupSoot() { 
        G.reset();
        Options.v().set_prepend_classpath(true); //-pp
        Options.v().set_whole_program(true); //-w
        Options.v().set_allow_phantom_refs(true);
        List<String> processdirs = new ArrayList<>();
        processdirs.add(this.jarFile);
        Options.v().set_process_dir(processdirs);
        Options.v().set_soot_classpath(this.sourceDirectory);
        Scene.v().loadNecessaryClasses();
    }

    // Preprocess the sink info file to identify vulnerable classes and the corresponding entry point
    // for arbitrary classes 
    public void preProcess() {
        // Create the set of reachable nodes in the gadget graph which will be used to identify reachable gadgets
        List<GadgetVertexSerializable> reachableNodes = findReachable(); 
        File tmpFile = new File(this.sinksInfo);
        String pattern = "Vulnerable Class:([\\s\\S]+) Vulnerable Method:([\\s\\S]+) Vulnerable Argument:([\\s\\S]+) Time:([\\d]+)";
        Pattern r = Pattern.compile(pattern);
        try {
            Scanner scanner = new Scanner(tmpFile);
            while (scanner.hasNextLine()) {
                // The line is "Vulnerable Class:org.apache.commons.LazyMap" so we split on : and add
                // just the class name
                String line = scanner.nextLine();
                // We flagged a class based on being able to pass an arbitrary object to one of its gadgets
                if (line.startsWith("Vulnerable Class:") && line.contains("Vulnerable Method:")) {
                    // Eg. Vulnerable Class:org.apache.click.control.Column$ColumnComparator Vulnerable Method:<org.apache.click.control.Column$ColumnComparator: int stringCompare(java.lang.Object,java.lang.Object)> Vulnerable Argument:class java.lang.Object Time:0
                    Matcher m = r.matcher(line);
                    assert m.find() : "Regex not matched, please double check format";
                    String clsName = m.group(1);
                    String methodName = m.group(2);
                    String argumentType = m.group(3);

                    initialSinkSet.add(methodName);
                    // Perform filteoring for overapproximated gadgets by checking if the
                    // poisoned arguemnt is used in a method invocation or not
                    boolean reachFunc = checkArgFlagged(clsName, methodName, argumentType);
                    if (reachFunc) {
                        // Comment the below addition if you want to solely check the efficiency of static filters
                        List<String> valueList = processedSinks.computeIfAbsent(clsName, k -> new ArrayList<String>());
		                // XXX: Had to add this dedup check since right now in the dynamic sink
		                // ID mode multiple times the same vulnerable method is
		                // getting flagged.  Fix it when you get the chance. 
		                if (! valueList.contains(methodName))
                            valueList.add(methodName);
                    } else {
                        continue;
                    }
                    finalSinkSet.add(methodName);

                    // If the user-controlled argument is flowing into
                    // vulnerable functionality, then flag this sink into
                    // `exploitable_sinks` file since during post-processing we
                    // will use this information to identify concretized chains
                    // that we want to prioritize first.  
                    boolean expFunc = checkArgFlowExploitable(clsName, methodName, argumentType);
                    if (expFunc) { 
                        exploitableSinks.add(methodName);
                    }
                } else if (line.startsWith("Vulnerable Class:")) { // We flagged a class based on passing instantiating one of its constructors with arbitrary class
                    // Eg. Vulnerable Class:org.apache.commons.collections.functors.TransformedPredicate Vulnerable Member:interface org.apache.commons.collections.Transformer
                    String[] parts = line.split(":");
                    String clsName = parts[1].split(" ")[0];
                    String memberName = parts[2].split(" ")[1];
                    // XXX: Perform special handling for array types. If we see
                    // that the member name starts with [L that means its array
                    // type (Ref: https://stackoverflow.com/questions/5085889/l-array-notation-where-does-it-come-from)
                    // Given such a member we convert it into the representation used by soot. So \Ljava.lang.Object is turned
                    // into java.lang.Object[] which is what is recognized by Soot
                    if (memberName.startsWith("[L")) {
                        // All but last character because Jazzer would add a semicolon at the end of the vulnerable name when it was an array type
                        String tmp = memberName.substring(2, memberName.length() - 1);
                        tmp += "[]";
                        LOGGER.debug(String.format("Pre-processing type:%s to %s", memberName, tmp));
                        memberName = tmp;
                    }
                    // We added the below assertion because we noticed that for
                    // array-types, jazzer would add a rogue ; at the end. We
                    // clean it in the previous conditional when its encountered and the below assertion is to ensure
                    // that we did not miss any other case to ensure correct sink ID
                    assert (! memberName.contains(";")) : "The vulnerable member contains a ;, please sanity-check";
                    sinkArgs.put(clsName, memberName);
                } 
                // Parse the information corresponding to vulnerable gadgets
                else if (line.startsWith("<")) {
                    // Check if the gadget is reachable as per the gadget graph
                    // from the set of known triggers. If it is only then add
                    // it to the consideration list
                    initialSinkSet.add(line);
                    for (GadgetVertexSerializable node: reachableNodes) {
                        if (line.equals(node.getMethodSignature())) {
                            String[] parts = line.split(" ");
                            String clsName = parts[0].substring(1, parts[0].length() - 1);
                            String gadgetName = parts[1] + " " + parts[2].substring(0, parts[2].length() - 1);
                            List<String> valueList = sinkMethods.computeIfAbsent(clsName, k -> new ArrayList<String>());
		    	            if (! valueList.contains(gadgetName))
                                valueList.add(gadgetName);
                        }
                    }
                }
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            LOGGER.debug("The file was not found");
            System.exit(1);
        }
    }

    // Reads in a serializable gadget graph encoding the call graoh. This is
    // used for an analysis pass 
    void readGraph() {
        try {
            FileInputStream fin = new FileInputStream("gadgetDB.store");
            ObjectInputStream oin = new ObjectInputStream(fin);
            SinkAnalysis.gadgetDBGraph = (Graph<GadgetVertexSerializable, DefaultEdge>) oin.readObject(); 
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
    }

    GadgetVertexSerializable getVertex(String key) {
        for (GadgetVertexSerializable vertex: gadgetDBGraph.vertexSet()) {
            if (vertex.node.getMethodSignature().equals(key)) 
                return vertex;
        }
        return null;
    }

    // Analysis specific to finding gadgets that are performing writes 
    public void runWriteAnalysis() {
        LOGGER.info("Running sink analysis for finding gadgets that perform file writes");
        List<GadgetVertexSerializable> reachableNodes = findReachable(); 
        for (GadgetVertexSerializable node: reachableNodes) {
            SootMethod sm = getSootMethod(node); 
            LOGGER.debug(String.format("Checking Class:%s Method:%s", sm.getName(), sm.getDeclaringClass().getName()));
            checkWrite(sm);
            if (SinkAnalysis.foundWrite) {
                LOGGER.info(String.format("Class:%s Potential Sink:%s", sm.getDeclaringClass().getName(), sm.getName()));
                List<String> valueList = processedSinks.computeIfAbsent(sm.getDeclaringClass().getName(), k -> new ArrayList<String>());
                valueList.add(sm.getSignature());
            }
        }
    }

    public void checkWrite(SootMethod sm) { 
        SinkAnalysis.foundWrite = false;
        JimpleBody body = (JimpleBody) sm.retrieveActiveBody();
        for (Unit u : body.getUnits()) {
            Stmt stmt = (Stmt) u;

            if(!stmt.containsInvokeExpr())
                continue;

            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            invokeExpr.apply(new AbstractJimpleValueSwitch() {
                @Override
                public void caseVirtualInvokeExpr(VirtualInvokeExpr v) {
                    if (v.getBase().getType().toString().equals("java.io.FileOutputStream") && v.getMethod().getName().toString().equals("write")) {
                        SinkAnalysis.foundWrite = true;
                    }
                }
                @Override
                public void defaultCase(Object v) {
                    super.defaultCase(v);
                }
            });
        }
    }

    public void runAnalysis() {
        for(Map.Entry<String, String> entry: sinkArgs.entrySet()) { 
            String clsName = entry.getKey();
            String memberName = entry.getValue();
            LOGGER.debug("Analyzing class:" + clsName);
            // System.out.println(String.format("Class:%s Member:%s", clsName, memberName));
            List<String> valueMap = sinkMethods.get(clsName);
            // This can occur if none of the gadgets corresponding to the
            // vulnerable class are reachable from the trigger gadgets
            if (valueMap == null) {
                LOGGER.debug("Skipping since there are no reachable gadgets corresponding to this class");
                continue;
            }
            SootClass sc = Scene.v().getSootClass(clsName);
            if (sc.isPhantom()) {
                LOGGER.debug(String.format("%s is a phantom class, skipping", sc.getName()));
                continue;
            }
            // Perform first pass which is an intra-procedural analysis pass to see
            // if there is a ref to the instantiated constructor argument type (found dynamically)
            SootMethod sm = null;
            // Flag to ensure that the transformation pass is only done once instead of redundantly for each
            // gadget
            boolean hasTransformationChecked = false;
            List<String> transformedArgTypes = null;
            for (String value : valueMap) {
                // Get the gadget which is to be analyzed
                LOGGER.debug("Analyzing gadget:" + value);
                sm = sc.getMethod(value);
                // XXX: Comment this if you're trying to gauge the effectiveness of the static analysis filters since
                // this would create classes with empty values in case all the gadgets get filtered out
                List<String> tempList = processedSinks.computeIfAbsent(clsName, k -> new ArrayList<String>());
		        if (tempList.contains(sm.getSignature())) {
		            LOGGER.debug("Already added to flagged list as a part of vulnerable method flagging module, skipping analysis");
		            continue;
		        }
                // Perform first pass where we perform intra-procedural pass on the gadget to
                // see if there is a ref to a variable of the same type as was intantiated with
                // an arbitrary class during the dynamic analysis phase
                LOGGER.debug("Performing intra-procedural analysis");
                findMethodFieldRef(sm, memberName);
                // If we have found a field ref in the gadget, then its been marked and do not need to
                // perform other analyis passes and can continue with analyzing others instead
                if (SinkAnalysis.foundRef) {
                    LOGGER.info(String.format("Class:%s Potential Sink:%s", clsName, sm.getName()));
                    List<String> valueList = processedSinks.computeIfAbsent(clsName, k -> new ArrayList<String>());
                    valueList.add(sm.getSignature());
                    LOGGER.debug("Found using intra-procedural");
                    continue;
                }
                // Perform second pass where we check if any of the methods called recursively by the gadgets
                // are using the instantiated constructor arguement. An example of this was `TransformedMap`
                // where the gadget `put` by itself had no references to a field arg
                LOGGER.debug("Performing recursive method analysis using the call graph");
                checkCallGraphRec(sm, memberName); 
                if (SinkAnalysis.foundRef) {
                    LOGGER.debug(String.format("Class:%s Potential Sink:%s", clsName, sm.getName()));
                    List<String> valueList = processedSinks.computeIfAbsent(clsName, k -> new ArrayList<String>());
                    valueList.add(sm.getSignature());
                    LOGGER.debug("Found using call-graph ref analysis");
                    continue;
                }

                // Perform third pass where we see if the instantiated
                // constructor argument has been transformed into another field
                // argument. If so, we try to see if any of the gadgets are
                // using the transformed field argument type instead. An
                // example of where this pass is necessary is to correctly
                // identify FastTreeMap.equals since there the field ref are
                // corresponding to `TreeMap` while the instantiated argument
                // is of type `SortedMap` which is then converted to
                // `SortedMap` by a constructor
                //
                LOGGER.debug("Performing transitive transformation anaylsis");
                if (! hasTransformationChecked) {
                    transformedArgTypes = checkTransformation(sc, memberName);
                    hasTransformationChecked = true;
                }
                if (transformedArgTypes.size() != 0) {
                    for(String argType: transformedArgTypes) {
                        // LOGGER.info("Checking with transformed type:" + argType);
                        findMethodFieldRef(sm, argType);
                        if (SinkAnalysis.foundRef) {
                            LOGGER.debug(String.format("Class:%s Potential Sink:%s", clsName, sm.getName()));
                            List<String> valueList = processedSinks.computeIfAbsent(clsName, k -> new ArrayList<String>());
                            valueList.add(sm.getSignature());
                            LOGGER.debug("Found using transformation pass analysis");
                            continue;
                        }
                    }
                }

            }
        }
    }
    
    List<String> checkTransformation(SootClass sc, String memberName) {
        List<String> transformedArgTypes = new ArrayList<String>();
        // if (! sc.getName().equals("org.apache.commons.collections.FastTreeMap")) {
        //     return transformedArgTypes;
        // }
        // First check the constructors of the declaring class of the gadgets to see if any
        // of them have a transformation happening for the instantiated argument type of interest
        for (SootMethod tmp: sc.getMethods()) {
            // Check if one of the constructors transforms the argument type of
            // interest to a instance field member. If so, we mark the
            // corresponding field member of interest as well
            if (tmp.getName().contains("<init>")) {
                JimpleBody body = (JimpleBody) tmp.retrieveActiveBody();
                for (Unit u : body.getUnits()) {
                    Stmt stmt = (Stmt) u;
                    if(stmt.containsInvokeExpr()) { 
                        InvokeExpr invokeExpr = stmt.getInvokeExpr();
                        invokeExpr.apply(new AbstractJimpleValueSwitch() {
                            @Override
                            public void caseSpecialInvokeExpr(SpecialInvokeExpr v) {
                                for (Value vv: v.getArgs()) {
                                    if (vv.getType().toString().equals(memberName)) {
                                        // LOGGER.info("Stmt:" + stmt);
                                        // LOGGER.info(String.format("Member:%s transformed to %s", vv.getType().toString(), v.getBase().getType().toString()));
                                        transformedArgTypes.add(v.getBase().getType().toString());
                                        break;
                                    }
                                }
                            }
                            @Override
                            public void defaultCase(Object v) {
                                super.defaultCase(v);
                            }
                        });
                    }
                }
            }
        }
        return transformedArgTypes;
    }


    boolean checkArgFlowExploitable(String clsName, String methodName, String argumentType) {
        // Here we try to identify sinks that can be confirmed to be
        // exploitable by checking if the identified sink performs vulnerable
        // functionality eg. Method.invoke, FileOutputStream.write This is in
        // line with how existing tools identify target sinks. The idea is to
        // first identify sinks that can have a user-controlled argument and
        // then see if that argument flows into a vulnerable function
        //
        // If the above condition is satisfied we return the method signature since we will
        // use this to flag concretized confirmed exploitable chains during the post eval phase
        //

        SootClass sc = Scene.v().getSootClass(clsName);
        if (sc.isPhantom()) {
            LOGGER.debug(String.format("%s is a phantom class, skipping", sc.getName()));
            return false;
        }
        SootMethod sm = sc.getMethod(getSubSignature(methodName));
        JimpleBody body = (JimpleBody) sm.retrieveActiveBody();
        // Poisoned method parameters
        List<Local> poisonedPar = new ArrayList<Local>();
        for (Local loc : body.getParameterLocals()) {
            // The argument type gotten from Jazzer starts as either `class` or `interface`
            // Eg. class java.lang.Object while the Local gotten from Soot does not have these
            // qualifiers and would only specify `java.lang.Object`.
            String[] parts = argumentType.split(" ");
            String tmpType = parts[1];
            // Normalize arr type
            if (tmpType.startsWith("[L")) {
                String tmp = tmpType.substring(2, tmpType.length() - 1);
                tmp += "[]";
                LOGGER.debug(String.format("Pre-processing type:%s to %s", tmpType, tmp));
                tmpType = tmp;
            }
            assert (parts[0].equals("class") || parts[0].equals("interface")) : "The member name does not start with `class` or `interface`. Please check"; 
            if (loc.getType().toString().equals(tmpType)) {
                // LOGGER.debug("Flagged poisoned argument");
                poisonedPar.add(loc);
            }
        }
        for (Unit u : body.getUnits()) {
            Stmt stmt = (Stmt) u;
            if(!stmt.containsInvokeExpr())
                continue;
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            // Check if the invoke expression is calling some known vulnerable functionality 
            SootMethod sm1 = invokeExpr.getMethod();
            if (sm1.getDeclaringClass().getName().equals("java.lang.reflect.Method") && sm1.getName().equals("invoke")) {
                if (parInLoc(invokeExpr, poisonedPar)) { 
                    LOGGER.debug("Stmt:" + stmt);
                    LOGGER.debug("Found user-controlled invocation of Method.invoke!");
                    return true; 
                }
            } else if (sm1.getDeclaringClass().getName().equals("java.io.FileOutputStream") && sm1.getName().equals("write")) {
                if (parInLoc(invokeExpr, poisonedPar)) { 
                    LOGGER.debug("Found user-controlled invocation of java.lang.FileOutputStream.write!");
                    return true;
                }
            }
        }
        return false;
    }

    boolean checkArgFlagged(String clsName, String methodName, String argumentType) {
        // One of the heuristics we use to identify potential sinks is to
        // see which gadgets are taking in as arguments parameter types that 
        // can be loaded in with user-controlled classes. An example of this is `aspectjweaver`
        // where the file location and what to write is passed through as function parameters
        // instead of conventional class-instantiated arguments which are then used to mount
        // the arbitrary file write exploit.
        //
        // There is a source of overapproximation in the case if this attacker-controlled
        // argument is not used for anything interesting. Case in point is in `cc3.1` where
        // BooleanComparator.equals is an overapproximated sink since the `Object` argument
        // passed to it is not used for some interesting functionality.
        //
        // The filter we are applying below is to check if the argument
        // passed in that is attacker-controlled is passed to a
        // function call.
        // LOGGER.debug("Performing argument passthrough check");
        //

        SootClass sc = Scene.v().getSootClass(clsName);
        if (sc.isPhantom()) {
            LOGGER.debug(String.format("%s is a phantom class, skipping", sc.getName()));
            return false;
        }

        SootMethod sm = sc.getMethod(getSubSignature(methodName));
        JimpleBody body = (JimpleBody) sm.retrieveActiveBody();
        // Poisoned method parameters
        List<Local> poisonedPar = new ArrayList<Local>();
        for (Local loc : body.getParameterLocals()) {
            // The argument type gotten from Jazzer starts as either `class` or `interface`
            // Eg. class java.lang.Object while the Local gotten from Soot does not have these
            // qualifiers and would only specify `java.lang.Object`.
            String[] parts = argumentType.split(" ");
            String tmpType = parts[1];
            // Normalize arr type
            if (tmpType.startsWith("[L")) {
                String tmp = tmpType.substring(2, tmpType.length() - 1);
                tmp += "[]";
                LOGGER.debug(String.format("Pre-processing type:%s to %s", tmpType, tmp));
                tmpType = tmp;
            }
            assert (parts[0].equals("class") || parts[0].equals("interface")) : "The member name does not start with `class` or `interface`. Please check"; 
            if (loc.getType().toString().equals(tmpType)) {
                // LOGGER.debug("Flagged poisoned argument");
                poisonedPar.add(loc);
            }
        }
        // Local paramLocal = body.getParameterLocal(0);
        for (Unit u : body.getUnits()) {
            Stmt stmt = (Stmt) u;
            if(!stmt.containsInvokeExpr())
                continue;
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            if (parInLoc(invokeExpr, poisonedPar))
                return true;
        }
        return false;
    }

    boolean parInLoc(InvokeExpr invokeExpr, List<Local> poisonedPar) {
        // Helper function to check if the poisoned argument is used inside the invocation expression
        for ( Value val:invokeExpr.getArgs()) {
            for (Local loc : poisonedPar) {
                if (val.equivTo(loc)) {
                    // LOGGER.debug("Poisoned parameter passed to a method invocation");
                    return true;
                }
            }
        }
        return false;
    }

    SootMethod getSootMethod(GadgetVertexSerializable vertex) {
        String clsName = vertex.getClsName();
        SootClass sc = Scene.v().getSootClass(clsName);
        SootMethod sm = sc.getMethod(getSubSignature(vertex.getMethodSignature()));
        return sm;
    }

    // Create the subsignature from the signature as represented in soot
    // Signature: <org.apache.commons.collections.collection.PredicatedCollection: void validate(java.lang.Object)>
    // Sub-signature: void validate(java.lang.Object)
    String getSubSignature(String signature) {
        String[] parts = signature.split(":");
        return parts[1].substring(1, parts[1].length() - 1);
    }

    void checkCallGraphRec(SootMethod sm, String memberName) {
        GadgetVertexSerializable vertex = getVertex(sm.getSignature());
        List<GadgetVertexSerializable> workList = new ArrayList<GadgetVertexSerializable>();
        List<GadgetVertexSerializable> seenNodes = new ArrayList<GadgetVertexSerializable>();
        workList.add(vertex);
        // Recursively go through the targets of the gadget in question to see if any of those
        // methods have a ref of interest
        while (!workList.isEmpty()) {
            GadgetVertexSerializable candidate = workList.remove(0);
	    try {
            	SootMethod tmp = getSootMethod(candidate);
            	LOGGER.debug("Analyzing descendant:" + candidate.getMethodSignature());
            	findMethodFieldRef(tmp, memberName); 
	    } catch (java.lang.RuntimeException e) {
		LOGGER.debug("No method found for:" + candidate);
	    }

            if (SinkAnalysis.foundRef)
                return;

            for(DefaultEdge e: gadgetDBGraph.outgoingEdgesOf(candidate)) {
                if (seenNodes.contains(gadgetDBGraph.getEdgeTarget(e))) {
                    continue;
                }
                workList.add(gadgetDBGraph.getEdgeTarget(e));
                seenNodes.add(gadgetDBGraph.getEdgeTarget(e));
            }
        }
    }

    // Iterate through statements in the method to see if any of them contains a field
    // ref to the argument of interest
    public void findMethodFieldRef(SootMethod sm, String memberName) {
        SinkAnalysis.foundRef = false;
        JimpleBody body = (JimpleBody) sm.retrieveActiveBody();
        // int c = 1;
        for (Unit u : body.getUnits()) {
            Stmt stmt = (Stmt) u;
            // LOGGER.debug(String.format("(%d): %s", c, stmt ));
            // c += 1;
            if(stmt.containsFieldRef()) { 
                checkFieldRef(memberName, stmt);
                if (SinkAnalysis.foundRef) {
                    break;
                }
            }
        }
    }

    public void checkFieldRef(String memberName, Stmt stmt) {
        FieldRef fieldRef = stmt.getFieldRef();
        fieldRef.apply(new AbstractRefSwitch() {
            @Override
            public void caseInstanceFieldRef(InstanceFieldRef v) {
                // LOGGER.debug("Stmt:" + stmt);
                // LOGGER.debug("Type:" + v.getFieldRef().type().toString());
                if (v.getFieldRef().type().toString().equals(memberName)) {
                    SinkAnalysis.foundRef = true;
                    LOGGER.debug("Field ref found successfully");
                }
            }
        });
    }

    // Find all the reachable nodes in the gadget graph from the set of specified triggers 
    public static List<GadgetVertexSerializable> findReachable() {

        List<GadgetVertexSerializable> workList = new ArrayList<GadgetVertexSerializable>();
        List<GadgetVertexSerializable> viableNodes = new ArrayList<GadgetVertexSerializable>();
        int reachableEdges = 0;

        Iterator<GadgetVertexSerializable> it = gadgetDBGraph.vertexSet().iterator(); 

        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            if (item.getType().equals("Trigger")) {
                workList.add(item);
            }
        }

        while (! workList.isEmpty()) {
            GadgetVertexSerializable candidate = workList.remove(0);
            // Count the number of edges as well for bookkeeping
            reachableEdges += gadgetDBGraph.outDegreeOf(candidate);  
            for(DefaultEdge e: gadgetDBGraph.outgoingEdgesOf(candidate)) {
                GadgetVertexSerializable v = gadgetDBGraph.getEdgeTarget(e);
                // If we have seen this node before continue without adding it to the worklist
                if (viableNodes.contains(v)) 
                    continue;
                viableNodes.add(v);
                workList.add(v);
            }
        }
        LOGGER.info("Number of reachable nodes:" + viableNodes.size());
        LOGGER.info("Number of reachable edges:" + reachableEdges);
        return viableNodes;
    }

    // Dump the flagged processed sinks to a <name_of_sinkfile>_processed
    public void dumpProcessedSinks() {
        String outFile = null;
        try {
            outFile = this.sinksInfo + "_processed"; 

            // Dump each of the flagged sinks to the outfile. This file will then
            // need to be processed by eval/parse_sinks.py to create code that can
            // be put into the static and dynamic analysis module respectively
            LOGGER.info("Writing processed sinks to:" + outFile);
            FileWriter fw = new FileWriter(outFile);
            BufferedWriter bw = new BufferedWriter(fw);
            for (Map.Entry<String, List<String>> entry: processedSinks.entrySet()) {
                for (String gadget: entry.getValue()) {
                    finalSinkSet.add(gadget);
                    bw.write(gadget);
                    bw.newLine();
                }
            }
            bw.close();
        } catch (IOException e) {
            LOGGER.info("Could not write processed sinks to:" + outFile);
            System.exit(1);
        }
    }

    // Dump serialized version of the sinks which can then be read bake during the final gadget graph creation phase
    public void dumpSerializedSinks() {
        String outFile = null;
        try {
            // Create the sink representation used during gadget graph creation
            Map<String,List<String>> outMap = new HashMap<String,List<String>>();
            for (Map.Entry<String, List<String>> entry: processedSinks.entrySet()) {
                // Get soot methoid name
                SootClass sc = Scene.v().getSootClass(entry.getKey());
                List<String> tmpList = new ArrayList<String>();
                for (String gadget: entry.getValue()) {
                    SootMethod sm = sc.getMethod(getSubSignature(gadget));
                    tmpList.add(sm.getName());
                }
                outMap.put(entry.getKey(), tmpList);
            }

            // Write the serialized version of hashmap
            outFile = this.sinksInfo + "_processed.serialized"; 
            FileOutputStream fos=new FileOutputStream(new File(outFile));
            ObjectOutputStream oos=new ObjectOutputStream(fos);
            oos.writeObject(outMap);
            oos.flush();
            oos.close();
            fos.close();

        } catch (IOException e) {
            LOGGER.info("Could not write processed sinks to:" + outFile);
            System.exit(1);
        }
    }

    public void dumpExploitableSinks() {
        String outFile = null;
        try {
            outFile = this.sinksInfo + "_exploitable"; 
            LOGGER.info("Confirmed exploitable sinks:" + exploitableSinks.size());

            // Dump each of the flagged sinks to the outfile. This file will then
            // need to be processed by eval/parse_sinks.py to create code that can
            // be put into the static and dynamic analysis module respectively
            LOGGER.info("Writing exploitable sinks to:" + outFile);
            FileWriter fw = new FileWriter(outFile);
            BufferedWriter bw = new BufferedWriter(fw);
            for (String gadget : exploitableSinks) {
                bw.write(gadget);
                bw.newLine();
            }
            bw.close();
        } catch (IOException e) {
            LOGGER.info("Could not write exploitable sinks to:" + outFile);
            System.exit(1);
        }
    }

    // Print the initial and final sink set size along with exploitable sinks found
    public void dumpRelevantStats() {
        LOGGER.debug("==CULLED SINKS==");
        for (String gadget: initialSinkSet) {
            if (! finalSinkSet.contains(gadget))
                LOGGER.debug(gadget);
        }
        LOGGER.debug("==FINAL SINKS==");
        for (String gadget: finalSinkSet)
            LOGGER.debug(gadget);
        LOGGER.info("Exploitable sink set size:" + exploitableSinks.size());
        LOGGER.info("Initial sink set size:" + initialSinkSet.size());
        LOGGER.info("Final sink set size:" + finalSinkSet.size());
    }
}
