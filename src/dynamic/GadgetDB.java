package com.example;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.*;

import analysis.GadgetVertexSerializable;
import analysis.GadgetMethodSerializable;

import java.io.Serializable;
import java.io.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

import org.apache.log4j.Logger;
// import org.apache.logging.log4j.Logger;

public class GadgetDB {

    // Rootpath where the auxiliary data can be found from which this class is deserialized
    private static final Logger LOGGER = Logger.getLogger(GadgetDB.class);
    static String rootPath = "/root/SeriFuzz/src/static/";
    // This indicates which particular path was chosen to be concretized. Since
    // AllDirectedPaths is ordered we can use this ID to uniquely identify
    // which path is being exercised
    public static int currentPathID; 
    // This list contains the unique method ID for each of the gadgets as per
    // the fnIDMap.store generated from the static analysis. Its used for
    // coverage tracking and keeping track of how much progress did we make
    // along a path
    // public static List<int> pathVertexIndices;


    // Create a cache of all well-formed objects created during a fuzzing
    // campaign
    public static Map<GadgetVertexSerializable, List<Object>> globalCache = new HashMap<GadgetVertexSerializable, List<Object>>();

    public static Graph<GadgetVertexSerializable, DefaultEdge> gadgetDBGraph = readDB(); 
    public static Set<GadgetVertexSerializable> triggerSet = new HashSet<GadgetVertexSerializable>();
    public static Set<GadgetVertexSerializable> sinkSet = new HashSet<GadgetVertexSerializable>();
    public static List<GraphPath<GadgetVertexSerializable, DefaultEdge>> paths;

    public static Graph<GadgetVertexSerializable, DefaultEdge> readDB() {
        Graph<GadgetVertexSerializable, DefaultEdge> temp = null;
        try {
            FileInputStream fin = new FileInputStream(rootPath + "gadgetDB.store");
            ObjectInputStream oin = new ObjectInputStream(fin);
            temp = (Graph<GadgetVertexSerializable, DefaultEdge>) oin.readObject(); 

        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
        return temp;
    }

    public static void findAllPaths() {
        AllDirectedPaths<GadgetVertexSerializable, DefaultEdge> allPaths = new AllDirectedPaths<>(gadgetDBGraph);
        paths = allPaths.getAllPaths(triggerSet, sinkSet, true, SeriFuzz.maxPathLength);
        // if (sinkSet.size() != 0) {
        //     paths = allPaths.getAllPaths(triggerSet, sinkSet, true, SeriFuzz.maxPathLength);
        // } else {
        //     // Check if the sinkset is empty, if that is the case that means the
        //     // triggers are the sinks. An example of this commons beanutils where
        //     // the "trigger" as per our definition is the sink
        //     // (BeanComparator.compare). In such a case, the path is just gonna be
        //     // the trigger gadget. Well technically the true trigger as setup in
        //     // `SetupPayload` pointing to these triggers.
        //     LOGGER.info("Sink set is empty. We infer that the triggers are the sinks and perform path inference accordingly. See comment here for further explanation.");
        //     sinkSet = Set.copyOf(triggerSet);
        //     paths = allPaths.getAllPaths(triggerSet, sinkSet, true, 0);
        // }
        // paths = allPaths.getAllPaths(triggerSet, sinkSet, true, 9);
        LOGGER.info("Total number of paths:" + paths.size());
    }

    static void printAllPaths() {
        // Iterate through each path and print the vertices
        int path_idx = 0;
        // Find the average number of nodes along all the paths as well 
        int avg_nodes = 0;
        for (GraphPath<GadgetVertexSerializable, DefaultEdge> path: paths) {
            List<GadgetVertexSerializable> vertexList = path.getVertexList();
            System.out.print("\n====\n");
            System.out.print(String.format("Idx:%d :: " , path_idx));
            for (GadgetVertexSerializable vertex : vertexList) {
                System.out.print("->" + vertex.toString());
            }
            System.out.print("\n====\n");
            avg_nodes += vertexList.size(); 
            path_idx += 1;
        }
        System.out.println("Average number of nodes:" + (avg_nodes / (path_idx + 1)));
        System.out.println("===Path lengths===");
        path_idx = 0;
        for (GraphPath<GadgetVertexSerializable, DefaultEdge> path: paths) {
            List<GadgetVertexSerializable> vertexList = path.getVertexList();
            // Identify the unique nodes in the chain
            Set<String> uniquePoints = new HashSet<String>();
            for (GadgetVertexSerializable node: vertexList) {
                uniquePoints.add(node.getClsName());
            }
            System.out.println(String.format("Idx:%d Length:%d Unique:%d", path_idx, vertexList.size(), uniquePoints.size())); 
            path_idx += 1;
        }
    }

    static void tagSourcesAndSinks() {
        Iterator<GadgetVertexSerializable> it = gadgetDBGraph.vertexSet().iterator(); 
        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            if (item.getType().equals("TriggerSink")) {
                triggerSet.add(item);
                sinkSet.add(item);
            } else if (item.getType().equals("Trigger")) {
                triggerSet.add(item);
            } else if (item.getType().equals("Sink")) {
                sinkSet.add(item);
            }
        }
        LOGGER.info("Total number of triggers:" + triggerSet.size());
        LOGGER.info("Total number of sinks:" + sinkSet.size());
    }

    // From the viable paths discovered statically choose one path
    // to exercise dynamically and create a payload for
    public static GraphPath<GadgetVertexSerializable, DefaultEdge> pickPath() {
        // Choose one of the paths randomly 
	    GadgetDB.currentPathID = ThreadLocalRandom.current().nextInt(0, paths.size()); 
        GraphPath<GadgetVertexSerializable, DefaultEdge> candidate = paths.get(GadgetDB.currentPathID);
        // // Accumulate all the vertex ID's corresponding to the path
        // List<int> tmp = new ArrayList<>();
        // for (GadgetVertexSerializable vertex: candidate.getVertexList()) {
        //     // Find the id corresponding to the gadget name
        //     int tmpIdx = TrackStatistics.idMap.indexOf(vertex.getQualifiedName());
        //     tmp.add(tmpIdx);
        // }
        // GadgetDB.pathVertexIndices = tmp;

        if (LOGGER.isDebugEnabled()) {
            String pathStr = getStrPath(candidate);
            LOGGER.debug("Chosen Path:" + pathStr);
            LOGGER.debug("Chosen Path ID:" + GadgetDB.currentPathID);
        }
        return candidate;
    }

    // Print string representation of the path being tested from the gadget  DB
    public static String getStrPath(GraphPath<GadgetVertexSerializable, DefaultEdge> candidate) {
        List<GadgetVertexSerializable> vertexList = candidate.getVertexList();
        String pathStr = "";
        for (GadgetVertexSerializable vertex : vertexList) {
            pathStr += vertex.toString();
            pathStr += " -> ";
        }
        return pathStr;
    }

    public static boolean concretizePathNoGG(GraphPath<GadgetVertexSerializable, DefaultEdge> candidate, FuzzedDataProvider data) {
        // Try to concretize the given node
        List<GadgetVertexSerializable> vertexList = candidate.getVertexList();
        GadgetVertexSerializable node = vertexList.get(0);
        LOGGER.debug("Picking node:" + node.getClsName());
        List<Object> objList = ObjectFactory.getObjects(node, data); 
        if (objList == null) {
                LOGGER.debug("The object for this class could not be created" + node.getClsName());
                return false;
        }
        else {
            // LOGGER.debug("Putting object in local cache");
            Class<?> key = ObjectFactory.getClass(node.getClsName());
            Meta.localCache.put(key, objList.get(0));
            return true;
        }
    }

    // For a chosen path, try to create a concrete payload
    public static boolean concretizePath(GraphPath<GadgetVertexSerializable, DefaultEdge> candidate, FuzzedDataProvider data) {

        // Traverse the path from the sink to source and try to create
        // well-formed objects for each node on the path
        List<GadgetVertexSerializable> vertexList = candidate.getVertexList();
        ListIterator<GadgetVertexSerializable> revIterator = vertexList.listIterator(vertexList.size());
        // System.out.println("Concretizing path");
        while (revIterator.hasPrevious()) {
            GadgetVertexSerializable node = revIterator.previous();

            LOGGER.debug("Concretizing path..");
            List<Object> objList = ObjectFactory.getObjects(node, data); 
            if (objList == null) {
                LOGGER.debug("The object for this class could not be created:" + node.getClsName());
                return false;
            }
            else {

                TrackStatistics.correctInstantiations += 1;

                // LOGGER.debug("Putting object in local cache");
                Class<?> key = ObjectFactory.getClass(node.getClsName());
                Meta.localCache.put(key, objList.get(0));
                // boolean didPass = validateSubPath(node, objList);
                // if (didPass) {
                //     // If the subpath corresponds to the trigger gadget then we 
                //     // do not try to bookkeep it as a correct invocation since we skipped
                //     // validating it
                //     if (!node.getType().equals("Trigger")) {
                //         TrackStatistics.correctInvocations += 1;
                //     }
                //     // LOGGER.debug("Adding object to global cache");
                //     // if (globalCache.containsKey(node)) {
                //     //     LOGGER.debug("Overwriting a well-formed object in global cache");
                //     // }
                //     // globalCache.put(node, objList);
                // }
                // else {
                //     LOGGER.debug("The gadget could not be invoked correctly with the synthesized arguments");
                //     // return false;
                // }
            }
        }
        
        // GadgetDB.concretizedPaths += 1 ; // Total number of paths successfully concretized

        return true;
    }

    // Check if the objects created corresponding to a specific gadget allow
    // for the dynamic execution by employing reflection 
    static boolean validateSubPath(GadgetVertexSerializable candidate, List<Object> objList) {

        // XXX: Double-check if this assumption is valid
        // If the vertex being validated corresponds to a trigger gadget then we do not
        // try to validate it by invoking the method
        LOGGER.debug("Validating sub path");
        if (candidate.getType().equals("Trigger")) {
            LOGGER.debug("Trigger gadget identified, skipping validation");
            return true;
        }
        // Get the class object corresponding to the gadget being tested
        Object clsObject = objList.get(0);

        // Check if class object is null
        if (clsObject == null) {
            LOGGER.debug("Null class object..skipping");
            return false;
        }
        Class<?> targetClass = ObjectFactory.getClass(candidate.getClsName());
        // Get the method corresponding to the gadget being tested
        Method gadget = ObjectFactory.getMethod(targetClass, candidate.getQualifiedName());
        // The parameter list is created from all the elements in the objlist
        // except the first one which corresponds to the declaring class object
        List<Object> parameterList = new ArrayList<Object>(objList.subList(1, objList.size()));
        // LOGGER.debug("Parameter List size:" + parameterList.size());
        
        // Invoke the method with the synthesized arguments
        try {
            gadget.setAccessible(true);
            gadget.invoke(clsObject, parameterList.toArray());
            // LOGGER.debug("Successfully validated");
        } catch (InvocationTargetException | IllegalAccessException | IllegalArgumentException x) {
            LOGGER.debug(String.format("Invocation of %s failed: %s\n", gadget.getName(), x.getCause()));
            return false;
        } catch (NullPointerException e) {
            // For now consider this a successful invocaton since it can occur in the case
            // the method argument provided is null
            LOGGER.debug("Null pointer exception occurred");
            // e.printStackTrace();
            return false;
        } catch (Exception e) {
            LOGGER.debug("Some other exception was caught");
            // e.printStackTrace();
            return false;
        }
        return true;
    } 


    // Sanity-check measure to ensure that the deserialized structure has sane set of vertices
    static void showVertices() {
        Iterator<GadgetVertexSerializable> it = gadgetDBGraph.vertexSet().iterator(); 
        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            System.out.println("Key:" + item);
        }
    }

    // Find all the reachable nodes in the gadget graph from the set of specified triggers 
    public static List<GadgetVertexSerializable> findReachable() {

        List<GadgetVertexSerializable> workList = new ArrayList<GadgetVertexSerializable>();
        List<GadgetVertexSerializable> viableNodes = new ArrayList<GadgetVertexSerializable>();

        Iterator<GadgetVertexSerializable> it = gadgetDBGraph.vertexSet().iterator(); 
        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            if (item.getType().equals("Trigger")) {
                workList.add(item);
                // Adding the entry points into the lib as viable nodes for sink ID as well.
                // An example where this is necessary is Click1 where ColumnComparator.compare is
                // the sink and the trigger as well
                // LOGGER.debug("Adding item:" + item);
                viableNodes.add(item);
            }
        }

        while (! workList.isEmpty()) {
            GadgetVertexSerializable candidate = workList.remove(0);
            for(DefaultEdge e: gadgetDBGraph.outgoingEdgesOf(candidate)) {
                GadgetVertexSerializable v = gadgetDBGraph.getEdgeTarget(e);
                // If we have seen this node before continue without adding it to the worklist
                if (viableNodes.contains(v)) 
                    continue;
                viableNodes.add(v);
                workList.add(v);
            }
        }
        LOGGER.info("Number of viable nodes:" + viableNodes.size());
        return viableNodes;
    }
    
}
