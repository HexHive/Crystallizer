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

public class GadgetMethod {

    private static final Logger LOGGER = Logger.getLogger(GadgetMethod.class);
    final SootClass cls;  // Class in which the method is contained
    final SootMethod method; // Name of the method
    final String type; // Type of the gadget
    final String qualifiedName; //  Name of the method that can be used for comparison against what is provided by Method class in java with some post-processing. 

    public String keyString() {
        // We return the unique numeric ID assigned to each SootMethod instead
        // of the string ID to make the graph vertices look more reasonable
        // return Integer.toString(cls.getNumber()) + Integer.toString(method.getNumberedSubSignature().getNumber());

        // Returns the entire signature including the class name
		// Eg. <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
        return this.method.getSignature();
    }

    GadgetMethod(SootMethod method) {
        this.cls = method.getDeclaringClass();
        if (GadgetID.isTrigger(method) && GadgetID.isSink(method)) {
            // This case applies to one-gadget chains from the trigger as was the case for commons beanutils where
            // we would jump from PriorityQueue.compare to Beancomparator.compare and that would be the entire chain
            this.type = "TriggerSink";
        } else if (GadgetID.isTrigger(method)) {
            this.type = "Trigger";
        } else if (GadgetID.isSink(method)) {
            this.type = "Sink";
        } else { 
            this.type = "Chain";
        }
        this.method = method;
        this.qualifiedName = buildQualifiedName(method);
    }

    // Method method in java when queried to give string ID outputs something like
    // ```
    // public java.lang.Object org.apache.commons.collections.map.LazyMap.get(java.lang.Object)
    // ```
    // We don't care about access specifiers but we do care about the return
    // type along with method name and its arguments. The reason we care about
    // the return type is because annonymous classes would allow the same
    // method with different return type to be specified
    //
    // For the sootmethod name we try to post-process the string given by getSignature which as follows:
    //```
    // <org.apache.commons.collections.map.LazyMap: java.lang.Object get(java.lang.Object)>
    // ```
    // We post-process this string to resemble the one which we will be using to compare against what we get from the method method in java
    //
    public static String buildQualifiedName(SootMethod method) {
        String sootSignature = method.getSignature();
		String[] splited = sootSignature.split(" ");
        String clsName = splited[0].substring(1, splited[0].length() - 1);
        String returnType = splited[1];
        String methodWithParameters = splited[splited.length - 1].substring(0, splited[splited.length - 1].length() - 1);
        return returnType + " " + clsName + "." + methodWithParameters;
    }

    String getMethodName() {
        return this.method.getName();
    }

    // Returns the method signature with fully qualified class name
    // eg <org.foo.bar: void baz(Object meh)>
    String getSignature() {
        return this.method.getSignature();
    }

    String getClassName() {
        return this.cls.getName();
    }

}

// Helper to ID the type of the gadget
class GadgetID {

    private static final Logger LOGGER = Logger.getLogger(GadgetID.class);

    static String[] dangerousFunctions = new String[] {
       "java.lang.Runtime.exec" 
       };


    // Check if the gadget is a trigger gadget
    public static boolean isTrigger(SootMethod sm) {
        for(String entry : LibAnalysis.entryPoints) {  
            if (entry.equals(sm.getName())) {
               LOGGER.debug("Trigger gadget identified"); 
               return true;
            }  
        }
        return false;
        // if (sm.getName().equals("readObject")) { 
        //     LOGGER.debug("Trigger gadget identified");
        //     return true;
        // } else { 
        //     return false;
        // }
    }
    

    // Check if the gadget is a sink gadget by looking 
    // if the method calls dangerous functionality
    public static boolean isSink(SootMethod sm) {
        for(Map.Entry<String, List<String>> sink: LibAnalysis.sinks.entrySet()) {  
            String clsName = sink.getKey();
            List<String> methodNames = sink.getValue();
            for (String methodName: methodNames) {
                if (clsName.equals(sm.getDeclaringClass().getName()) && methodName.equals(sm.getName())) {
                   LOGGER.debug("Sink gadget identified"); 
                   return true;
                }  
            }
        }
        return false;
        // CallGraph callGraph = Scene.v().getCallGraph();
        // for(Iterator<Edge> it = callGraph.edgesOutOf(sm); it.hasNext(); ){
        //     Edge edge = it.next();
        //     String _fullname = (edge.tgt().getDeclaringClass()) + "." +  (edge.tgt()).getName();
        //     // LOGGER.debug("Called function:" + _fullname);
        //     for(String function : dangerousFunctions) {
        //         if (function.equals(_fullname)) {
        //             LOGGER.debug("Sink gadget identified");
        //             return true;
        //         }
        //     }
        // }
        // return false;
    }

    // Check if the candidate has a superclass and if its serializable We do
    // this because if the superclass is serializable the child class is
    // serializable too
    public static boolean isSerializable(SootClass sc) {
        if (sc.implementsInterface("java.io.Serializable")) 
            return true;
        SootClass scOrig = sc;
        // Recursively identify if it has a serializable parent
        if (sc.hasSuperclass()) {
            do {
                SootClass ssc = sc.getSuperclass();
                if (ssc.implementsInterface("java.io.Serializable"))
                    return true;
                // Check recursively the interfaces that it implements to see if any of them are serializable
                for (SootClass ssci : ssc.getInterfaces()) {
                    LOGGER.debug("Checking interface:" + ssci.getName());
                    if (isInterfaceSerializable(ssci)) {
                        LOGGER.debug("Is serializable");
                        return true;
                    }
                }
                sc = ssc;
            } while (sc.hasSuperclass());
        }
        LOGGER.debug("It has interfaces:" + scOrig.getInterfaceCount());
        // Recursively identify if it has a serializable interface
        if (scOrig.getInterfaceCount() != 0) {
            // Check recursively the interfaces that it implements to see if any of them are serializable
            for (SootClass ssci : scOrig.getInterfaces()) {
                LOGGER.debug("Checking interface:" + ssci.getName());
                if (isInterfaceSerializable(ssci)) {
                    LOGGER.debug("Is serializable");
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isInterfaceSerializable(SootClass sc) {
        if (sc.implementsInterface("java.io.Serializable"))
            return true;
        for (SootClass ssci: sc.getInterfaces()) {
            LOGGER.debug("Checking interfaces recursively:" + ssci.getName());
            if (isInterfaceSerializable(ssci)) 
                return true;
        }
        return false;
    }

}
