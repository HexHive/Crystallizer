package analysis; 

import soot.*;
import soot.jimple.*;
import soot.options.Options;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.nio.*;
import org.jgrapht.nio.dot.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;

import java.util.*;
import java.io.*;
import org.apache.log4j.Logger;

public class GadgetDB {

    private static final Logger LOGGER = Logger.getLogger(GadgetDB.class);

    static List<GadgetMethod> triggerList = new ArrayList<GadgetMethod>();
    public static List<GadgetMethod> sinkList = new ArrayList<GadgetMethod>();
    public static CallGraph callGraph; 
    public static Graph<GadgetVertex, DefaultEdge> gadgetDBGraph = new DefaultDirectedGraph<>(DefaultEdge.class);
    public static Graph<GadgetVertexSerializable, DefaultEdge> gadgetDBGraphSerializable = new DefaultDirectedGraph<>(DefaultEdge.class);
    public static int num_sinks = 0;
    public static int num_triggers = 0;

    // Add a gadget as a dependency to the graph 
    void addVertex(GadgetMethod gadget) {
        gadgetDBGraph.addVertex(new GadgetVertex(gadget));
        if (gadget.type.equals("Trigger")) {
            triggerList.add(gadget);
        } else if (gadget.type.equals("Sink")) {
            sinkList.add(gadget);
        }
    }

    // Remove vertices that have no incoming or outgoing edges
    void removeIsolatedNodes() {
        List<GadgetVertex> isolatedVertices = new ArrayList<GadgetVertex>();
        for (GadgetVertex vertex: gadgetDBGraph.vertexSet()) {
            if (gadgetDBGraph.degreeOf(vertex) == 0)
                isolatedVertices.add(vertex);
        }
        gadgetDBGraph.removeAllVertices(isolatedVertices);
    }

    void findInterestingPaths(SootMethod src, SootMethod dst) {
        GadgetVertex srcVertex = getVertex(src);
        GadgetVertex dstVertex = getVertex(dst);
        AllDirectedPaths<GadgetVertex, DefaultEdge> allPaths = new AllDirectedPaths<>(gadgetDBGraph);
        List<GraphPath<GadgetVertex, DefaultEdge>> paths = allPaths.getAllPaths(srcVertex, dstVertex, true, 5);
        LOGGER.info("Number of paths:" + paths.size());
    }

    void findConnectedNodes(SootMethod sink) {
        GadgetVertex dstVertex = getVertex(sink);
        List<GadgetVertex> workList = new ArrayList<GadgetVertex>();
        List<GadgetVertex> viableNodes = new ArrayList<GadgetVertex>();
        // Initialize worklist
        for (DefaultEdge e: gadgetDBGraph.incomingEdgesOf(dstVertex)) {
            workList.add(gadgetDBGraph.getEdgeSource(e));
            viableNodes.add(gadgetDBGraph.getEdgeSource(e));
        }
        while (!workList.isEmpty()) {
            LOGGER.debug("Worklist size:"+ workList.size());
            GadgetVertex candidate = workList.remove(0);
            for(DefaultEdge e: gadgetDBGraph.incomingEdgesOf(candidate)) {
                if (viableNodes.contains(gadgetDBGraph.getEdgeSource(e))) {
                    LOGGER.debug("Edge src already seen");
                    continue;
                }
                workList.add(gadgetDBGraph.getEdgeSource(e));
                viableNodes.add(gadgetDBGraph.getEdgeSource(e));
            }
        }
        LOGGER.info("Viable nodes:" + viableNodes.size());
    }

    void renderGraph() {
        DOTExporter<GadgetVertex, DefaultEdge> exporter = new DOTExporter<>();
        exporter.setVertexAttributeProvider((v) -> {
            Map<String, Attribute> map = new LinkedHashMap<>();
            map.put("label", DefaultAttribute.createAttribute(v.toString()));
            return map;
        });
        try {
            FileWriter fw = new FileWriter("out.dot");
            Writer writer = new StringWriter();
            exporter.exportGraph(gadgetDBGraph, writer);
            fw.write(writer.toString());
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    GadgetVertex getVertex(SootMethod sm) {
        for (GadgetVertex vertex: gadgetDBGraph.vertexSet()) {
            if (vertex.node.method.equals(sm)) 
                return vertex;
        }
        return null;
    }

    GadgetVertexSerializable getVertexSerializable(String key) {
        for (GadgetVertexSerializable vertex: gadgetDBGraphSerializable.vertexSet()) {
            if (vertex.node.getMethodSignature().equals(key)) 
                return vertex;
        }
        return null;
    }

    // Counts the number of edges and nodes in the callgraph generated by default
    void countCallGraphNodesEdges() {
        // Initialize the worklist
        List<MethodOrMethodContext> workList = new ArrayList<MethodOrMethodContext>();
        List<MethodOrMethodContext> viableNodes = new ArrayList<MethodOrMethodContext>();
        int callGraphEdges = 0;
        for(Iterator<MethodOrMethodContext> it = callGraph.sourceMethods(); it.hasNext();) {
            MethodOrMethodContext candidate = it.next();
            SootMethod method = candidate.method();
            // Doing this to skip entry points that are not belonging to the library
            SootClass sc = method.getDeclaringClass();
            if (LibAnalysis.libRules.excludeClass(sc.getName())) {
                continue;
            }
            // boolean shouldSkip = false;
            // for (String excluded: LibAnalysis.excludeList) {
            //     if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("com.sun.syndication"))) {
            //     // if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("javax."))) {
            //     // if (sc.getName().startsWith(excluded)) {
            //         shouldSkip = true;
            //         break;
            //     }
            // }
            // if (shouldSkip)
            //     continue;
            for (String entryPoint: LibAnalysis.entryPoints) {
                if (method.getName().equals(entryPoint)) {
                    workList.add(candidate);
                }
            }
        }

        while (! workList.isEmpty()) {
            MethodOrMethodContext candidate = workList.remove(0);
            for(Iterator<Edge> it = callGraph.edgesOutOf(candidate); it.hasNext();) {
                Edge e = it.next();
                MethodOrMethodContext v = e.getTgt();
                SootClass sc = v.method().getDeclaringClass();

                if (LibAnalysis.libRules.excludeClass(sc.getName())) {
                    continue;
                }
                // boolean shouldSkip = false;
                // for (String excluded: LibAnalysis.excludeList) {
                //     if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("com.sun.syndication"))) {
                // 	// if (sc.getName().startsWith(excluded) && (! sc.getName().startsWith("javax."))) {
                //     // if (sc.getName().startsWith(excluded)) {
                //         shouldSkip = true;
                //         break;
                //     }
                // }
                // if (shouldSkip)
                //     continue;
                callGraphEdges += 1;
                // If we have seen this node before continue without adding it to the worklist
                if (viableNodes.contains(v)) 
                    continue;
                viableNodes.add(v);
                workList.add(v);
            }
        }
        
        // LOGGER.info("Number of reachable nodes in vanilla callgraph:" + viableNodes.size());
        // LOGGER.info("Number of reachable edges in vanilla callgraph:" + callGraphEdges);
    }

    // // Iterate over the vertices to build edges
    void inferEdges() {
        // Iterate through all vertices
        for (GadgetVertex srcVertex : gadgetDBGraph.vertexSet()) {
            GadgetMethod src = srcVertex.node;
            LOGGER.debug("Checking method:" + src.getMethodName() + " from class:" + src.getClassName());
            // Ensure that the method is not abstract/native/phantom
            if (! src.method.isConcrete()) {
                LOGGER.debug("It is an abstract/native/phantom class, skipping..");
                continue;
            }
            // If the Soot-based callgraph has an edge add it 
            for(Iterator<Edge> it = callGraph.edgesOutOf(src.method); it.hasNext();) {
                Edge tmpEdge = it.next();
                LOGGER.debug("Method:" + tmpEdge.src() + " invokes method:"+ tmpEdge.tgt());
                GadgetVertex dstVertex = getVertex(tmpEdge.tgt());
                if (dstVertex != null) {
                    if ((srcVertex != null && dstVertex != null)) {
                        LOGGER.debug("Adding edge...");
                        gadgetDBGraph.addEdge(srcVertex, dstVertex);
                    }
                } else
                    LOGGER.debug(tmpEdge.tgt() + " does not have an instantiated clvertex");
            }
            // If the method has a superclass which declares the same method then add
            // edge from superclass to this class of type override
            // SootClass sc = src.cls.getSuperclass();
            // // If the superclass is as below then it is an interface type
            // if (sc.getName().equals("java.lang.Object")) {
            //     LOGGER.debug("This class does not have a superclass");
            //     continue;
            // }
            // for (SootMethod sm: sc.getMethods()) {
            //     if (sm.getName().equals(src.getMethodName())) {
            //         LOGGER.debug("This method can be overriden from class:" + sc.getName());
            //         GadgetMethod srcsrc = getVertex(sm); 
            //         if (srcsrc != null)
            //             addEdge(srcsrc, src, "Override");
            //         else 
            //             LOGGER.debug(sm.getName() + " from:" + sc.getName() + " has not been instantiated");
            //     }
            // }
        }
    }

    // Encode the graph as a map with keys as vertices and values as vertices
    // to which the key vertex has edges to and then flush it. The vertices
    // themselves are <classname.methodname>. We use this encoding to create a
    // serialized representation of the gadget DB which can be used by the
    // dynamic harness
    void encodeGraphFlush() {
        // Create a serializable representation of the gadgetDBGraph
        for (GadgetVertex vertex: gadgetDBGraph.vertexSet()) {
            String clsName = vertex.node.getClassName();
            String methodSignature = vertex.node.getSignature();
            String type = vertex.node.type;
            String qualifiedName = vertex.node.qualifiedName;
            LOGGER.debug("Qualified name:" + qualifiedName);
            GadgetVertexSerializable newVertex = new GadgetVertexSerializable(new GadgetMethodSerializable(clsName, methodSignature, type, qualifiedName));
            gadgetDBGraphSerializable.addVertex(newVertex);
        }
        // Add all the edges
        for (DefaultEdge e : gadgetDBGraph.edgeSet()) {
            GadgetVertex srcEdge = gadgetDBGraph.getEdgeSource(e); 
            GadgetVertex dstEdge = gadgetDBGraph.getEdgeTarget(e); 
            GadgetVertexSerializable tmpSrc = getVertexSerializable(srcEdge.toString());
            GadgetVertexSerializable tmpDst = getVertexSerializable(dstEdge.toString());
            if (tmpSrc == null || tmpDst == null) {
                LOGGER.info("No corresponding serializable edge found for:" + tmpSrc + "->" + tmpDst);
                System.exit(1);
            }
            gadgetDBGraphSerializable.addEdge(tmpSrc, tmpDst);
        }
        // Flush the graph to disk
        try {
            FileOutputStream fos = new FileOutputStream("gadgetDB.store");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(gadgetDBGraphSerializable);
            oos.close();
            fos.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    // Reads in a serializable graph and sanity-checks that the information
    // read in is the same as that was dumped
    void readGraphSerializable() {
        try {
            FileInputStream fin = new FileInputStream("gadgetDB.store");
            ObjectInputStream oin = new ObjectInputStream(fin);
            Graph<GadgetVertexSerializable, DefaultEdge> readGraph = (Graph<GadgetVertexSerializable, DefaultEdge>) oin.readObject(); 
            Iterator<GadgetVertexSerializable> it1 = readGraph.vertexSet().iterator(); 
            Iterator<GadgetVertexSerializable> it2 = gadgetDBGraphSerializable.vertexSet().iterator(); 
            // Sanity-check all vertices
            while (it1.hasNext() && it2.hasNext()) {
                GadgetVertexSerializable op1 = it1.next();
                GadgetVertexSerializable op2 = it2.next();
                assert op1.equals(op2) : "The serialized information is different from what was dumped"; 
            }
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
    }

    // Debug: Display edges of a specific class as per the Soot-generated CG
    void getSpecificEdgesSoot(String clsName, String methodName) {
        SootClass sc = Scene.v().getSootClass(clsName);
        SootMethod sm = sc.getMethodByName(methodName);
        for(Iterator<Edge> it = callGraph.edgesOutOf(sm); it.hasNext(); ) {
            Edge edge = it.next();
            LOGGER.info("Method:" + edge.src() + " invokes method:"+ edge.tgt());
        } 
    }

    // Debug: Iterate over all edges in the callgraph
    void iterateAllEdges() {
        Iterator<Edge> iteratorEdges = callGraph.iterator();
        while (iteratorEdges.hasNext()) {
            Edge edge = iteratorEdges.next();
            LOGGER.debug("Method:" + edge.src() + " invokes method:"+ edge.tgt());
        }
    }

    // Find all the reachable nodes in the gadget graph from the set of specified triggers 
    public static List<GadgetVertexSerializable> findReachable() {

        List<GadgetVertexSerializable> workList = new ArrayList<GadgetVertexSerializable>();
        List<GadgetVertexSerializable> viableNodes = new ArrayList<GadgetVertexSerializable>();
        int reachableEdges = 0;

        Iterator<GadgetVertexSerializable> it = gadgetDBGraphSerializable.vertexSet().iterator(); 

        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            if (item.getType().equals("Trigger") || item.getType().equals("TriggerSink")) {
                workList.add(item);
            }
        }

        while (! workList.isEmpty()) {
            GadgetVertexSerializable candidate = workList.remove(0);
            // Count the number of edges as well for bookkeeping
            reachableEdges += gadgetDBGraphSerializable.outDegreeOf(candidate);  
            for(DefaultEdge e: gadgetDBGraphSerializable.outgoingEdgesOf(candidate)) {
                GadgetVertexSerializable v = gadgetDBGraphSerializable.getEdgeTarget(e);
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
}

class GadgetEdge {

    GadgetMethod src;
    GadgetMethod dst;
    String type; // Edge type
    public GadgetEdge(GadgetMethod src, GadgetMethod dst, String type) {
        this.src = src;
        this.dst = dst;
        this.type = type;
    }

}
    

