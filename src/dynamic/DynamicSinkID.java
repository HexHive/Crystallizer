package com.example; 

import java.util.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.log4j.Logger;
import java.util.concurrent.ThreadLocalRandom;
import java.lang.reflect.Method;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.*;
import com.code_intelligence.jazzer.api.AutofuzzConstructionException;
import com.code_intelligence.jazzer.api.AutofuzzInvocationException;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import analysis.GadgetVertexSerializable;

class DynamicSinkID {

    private static final Logger LOGGER = Logger.getLogger(DynamicSinkID.class);

    // // Create a Map from the unique classes in the gadget graph to that of the
    // // reachable methods corresponding to that class 
    public static Map<String, List<MethodContainer>> methodMap = new HashMap<String, List<MethodContainer>>();
    public static Map<String, List<MethodContainer>> vulnerableMethodMap = new HashMap<String, List<MethodContainer>>();
    //
    // We need to do this deduplication because there could be multiple gadgets belonging to
    // the same class and therefore the random sampling might get biased towards specific classes
    // more than the others
    public static Object[] uniqueClasses = createArray();
    public static Object[] createArray() { 
        // The reason we perform this reachability analysis is because my
        // initial assumption was that the generated call graph from which the
        // gadget graph is generated would have the specified entry points as
        // graph sources but looking into it further we realized that that's
        // not the case. So we perform this reachability analyis to make sure
        // we only take into consideration classes that are reachable from the
        // trigger gadgets 
        LOGGER.debug("Performing reachable node analysis");
        List<GadgetVertexSerializable> reachableNodes = GadgetDB.findReachable();

        Set<String> uniquePoints = new HashSet<String>();
        // Unique points accumulated without performing the reachability
        // analysis This data structure is just there to see if the
        // reachability analyiss adds any benefit to identifying potential
        // sinks
        Set<String> uniquePointsNoReachable = new HashSet<String>();
        Iterator<GadgetVertexSerializable> it = GadgetDB.gadgetDBGraph.vertexSet().iterator(); 
        while (it.hasNext()) {
            GadgetVertexSerializable item = it.next(); 
            if (reachableNodes.contains(item)) {
                String clsName = item.getClsName();
                // Populate unique classes structure 
                LOGGER.debug("Reachable:" + item.toString());
                LOGGER.debug("Adding class:" + clsName);
                uniquePoints.add(clsName);

                // LOGGER.debug("Getting:" + clsName);
                List<MethodContainer> methods = methodMap.computeIfAbsent(clsName, k-> new ArrayList<MethodContainer>());
                try {
                    LOGGER.debug("Getting class:" + clsName);
                    Class<?> clazz = ObjectFactory.getClass(clsName);
                    LOGGER.debug("Getting method:" + item.getQualifiedName());
                    Method m = ObjectFactory.getMethod(clazz, item.getQualifiedName());  
                    if (m == null ) {
                        LOGGER.debug("No corresponding method definition found, skipping");
                        continue;
                    }
                    String sootSignature = item.toString();
                    methods.add(new MethodContainer(m, sootSignature));
                } catch(NoClassDefFoundError | ExceptionInInitializerError  | IllegalAccessError e) {
                    // LOGGER.info("Caught exception!");
                    LOGGER.debug("No class definition exists..skipping");
                    continue;
                }
            }
            uniquePointsNoReachable.add(item.getClsName());
        }

        LOGGER.debug(String.format("Original vertices:%d", GadgetDB.gadgetDBGraph.vertexSet().size()));
        LOGGER.debug(String.format("Dedup vertices with no reachability analysis:%d", uniquePointsNoReachable.size()));
        LOGGER.debug(String.format("Dedup vertices:%d", uniquePoints.size()));

        return uniquePoints.toArray();
    }

    // The targeted library specifies if there is some special exclusion needs
    // to be done in case.  Eg. vaadin we only consider the com.vaadin.*
    // classes for sink ID since we are not interested in the class belonging
    // to other jar files that are packaged along with it.  
    public static String targetLibrary = null;


    // Flagged classes through initialized constructors
    public static Set<String> vulnerableClasses = new HashSet<String>();
    // Flagged classes through candidate vulnerable methods
    public static Set<String> vulnerableClassesThroughMethods = new HashSet<String>();

    public static boolean testPotentialSinks(FuzzedDataProvider data) {

        // Flag to identify if the sink is flagged based on a method accepting a user-conntrolled object
        boolean vulnMethod = false;
        // Pick a serializable class at random
        int choice = ThreadLocalRandom.current().nextInt(0, uniqueClasses.length); 
        String className = (String) uniqueClasses[choice];

        MethodContainer mc = null;
        // We perform this exclusion in case a library has multiple different modules packaged
        // and we want to focus the analysis on a specific set of modules
        if (DynamicSinkID.targetLibrary.equals("vaadin1")) {
            if (! className.startsWith("com.vaadin")) {
                return false;
            }
        } else if (DynamicSinkID.targetLibrary.equals("commons_beanutils")) {
            if (! className.startsWith("org.apache.commons.beanutils")) {
                return false;
            }
        } else if (DynamicSinkID.targetLibrary.equals("aspectjweaver")) {
            if (! className.startsWith("org.aspectj")) {
                return false;
            }
        } else if (DynamicSinkID.targetLibrary.equals("coherence")) {
            if (! className.startsWith("com.tangosol")) {
                return false;
            }
        } 


        try {

            if (! vulnerableClasses.contains(className)) {
                Meta.initStack.clear();
                Meta.constructionSteps.clear();
                Class<?> targetClass = ObjectFactory.getClass(className);
                if (targetClass == null) {
                    return false;
                }
                // System.out.println("==Instantiating class==");
                Object clsObject = Meta.consume(data, targetClass);
            }
            
            // If the declaring class object was successfully created then try
            // to create arguments for the reachable methods and see if
            // arbitrary objects can be passed via those
            // Choose a random reachable method in the candidate class to instantiate arguments for
            List<MethodContainer> candidateMethods = methodMap.get(className);
            mc = candidateMethods.get(ThreadLocalRandom.current().nextInt(0, candidateMethods.size()));

            // Check if this chosen method has not already been flagged
            List<MethodContainer> vulnerableMethods = vulnerableMethodMap.computeIfAbsent(className, k-> new ArrayList<MethodContainer>());
            if (! vulnerableMethods.contains(mc)) {
                vulnMethod = true;
                Method m = mc.getMethod();
                // LOGGER.debug("Instantiating method:" + m.getName());
                Meta.initStack.clear();
                Meta.constructionSteps.clear();
                Meta.initStack.add(m.getName());
                Meta.constructionSteps.add(String.format("Instantiating method:%s", m.getName()));
                Object[] arguments = Meta.consumeArguments(data, m, null); 
            }
        } catch (java.lang.NoClassDefFoundError e ) { 
            LOGGER.debug("One of the composing classes/this class was not found.");
            return false;
        }
        catch (AutofuzzConstructionException e) {
            LOGGER.debug("The declaring class object could not be created");
            // e.printStackTrace();
            // System.exit(1);
            return false;
        } catch (AutofuzzInvocationException e) {
            LOGGER.debug("The arguments passed to the constructor were not well-formed");
            return false;
        } catch (Error e) {
            boolean isSink = false;
            // Hacky way of checking if its a error that we are interested in, we check if the construction
            // steps involved loading the jazzer class. We need to do this because in vaadin other errors were being caught
            // by jazzer and certain classes were being incorrectly flagged as being potential sinks
            for (String step: Meta.constructionSteps) {
                if (step.contains("jaz.Zer")) {
                    isSink = true;
                }    
            }

            // We called a false positive error, returning
            if (!isSink) {
                LOGGER.debug("False positive signal raised");
                return false;
            }

            // steps include loading the poison class from jazzer
            if (!vulnMethod) {
                LOGGER.debug(String.format("%s found to be vulnerable, logging it.", className));
                vulnerableClasses.add(className);
            } else {
                LOGGER.debug(String.format("%s found to be vulnerable through a vulnerable method, logging it.", className));
                List<MethodContainer> methods = vulnerableMethodMap.computeIfAbsent(className, k-> new ArrayList<MethodContainer>());
                methods.add(mc);
            }
            try {
                FileWriter fw = new FileWriter(LogCrash.crashDir + "potential_sinks", true);
                long elapsedTime = TrackStatistics.getTimeForCrash();
                BufferedWriter bw = new BufferedWriter(fw);
                if (!vulnMethod) {
                    // Get the penultimate element in the stack to identify instantiating which argument caused
                    // the poison class to be loaded. We write the penultimate member in the stack since the last element is the class
                    // itself which is being instantiated 
                    while (Meta.initStack.size() > 2) {
                        LOGGER.info(String.format("Popped member:%s", Meta.initStack.peek()));
                        Meta.initStack.pop();
                    }
                    bw.write(String.format("Vulnerable Class:%s Vulnerable Member:%s Time:%d", className, Meta.initStack.pop(), elapsedTime));
                    // List out all the potential gadgets (methods) as per the gadgetDB as well
                    Iterator<GadgetVertexSerializable> it = GadgetDB.gadgetDBGraph.vertexSet().iterator(); 
                    bw.newLine();
                    bw.write("==Potential Gadgets==");
                    bw.newLine();
                    while (it.hasNext()) {
                        GadgetVertexSerializable item = it.next(); 
                        if (item.getClsName().equals(className)) {
                            bw.write(item.toString());
                            bw.newLine();
                        }
                    }
                    bw.write("==Construction Steps==");
                    bw.newLine();
                    for (String step: Meta.constructionSteps) {
                        bw.write(step);
                        bw.newLine();
                    }
                } else {
                    // We pop till two elements are left because the last two
                    // elements correspond to the method being instantiated and
                    // the argument which caused the poison class to be loaded
                    while (Meta.initStack.size() > 2) {
                        LOGGER.info(String.format("Popped member:%s", Meta.initStack.peek()));
                        Meta.initStack.pop();
                    }
                    String vulnerableArg = Meta.initStack.pop();
                    String vulnerableMethod = Meta.initStack.pop();
                    // We use the qualified name since we need to it to get the SootMethod during the static filtering phase
                    bw.write(String.format("Vulnerable Class:%s Vulnerable Method:%s Vulnerable Argument:%s Time:%d", className, mc.getSootSignature(), vulnerableArg, elapsedTime));
                    bw.newLine();
                    bw.write("==Construction Steps==");
                    bw.newLine();
                    for (String step: Meta.constructionSteps) {
                        bw.write(step);
                        bw.newLine();
                    }
                }
                bw.close();
            } catch (IOException i) {
            }
            // System.exit(1);
        }
        return true;
    }
}

// Helper container class that is used in the methodMap
class MethodContainer {

    Method method;
    String sootSignature;

    MethodContainer(Method m, String sootSignature) {
        this.method = m;
        this.sootSignature = sootSignature;
    }

    Method getMethod() {
        return method;
    }

    String getSootSignature() {
        return sootSignature;
    }
}
