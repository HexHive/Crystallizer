package com.example;

// Autofuzz-specific imports
import java.lang.reflect.Executable;
import java.lang.reflect.Method;

import com.code_intelligence.jazzer.autofuzz.*;
import com.code_intelligence.jazzer.api.AutofuzzConstructionException;
import com.code_intelligence.jazzer.api.AutofuzzInvocationException;

import java.util.*;
import java.io.*;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import analysis.GadgetVertexSerializable;

import javax.xml.transform.Templates;


import org.apache.log4j.Logger;
// import org.objectweb.asm.Type;
// import org.apache.logging.log4j.Logger;

// This class interfaces with the autofuzz module to create well-formed objects
public class ObjectFactory {

    private static final Logger LOGGER = Logger.getLogger(ObjectFactory.class);

    public static List<Object> getObjects(GadgetVertexSerializable node, FuzzedDataProvider data) {
        // Get the name versions of the class for which the object is to be generated
        String className = node.getClsName();
        String qualifiedName = node.getQualifiedName();

        // Create an array which will hold the set of wellf-formed objects relevant to the gadget
        // The first index will hold the declaring class object and the rest of the indices will hold
        // objects corresponding to the parameters accepted by the method (gadget)
        List<Object> objectList = new ArrayList<Object>();
        Class<?> targetClass = getClass(className);
        if (targetClass == null) {
			LOGGER.debug("Empty class");
            return null;
        }

        try { 
            // Check if the object has already been synthesized while trying to concretize this path
            Object clsObject = Meta.consume(data, targetClass);
            LOGGER.debug("Successfully instantiated object for class:" + className);
            objectList.add(clsObject);
        } catch (AutofuzzConstructionException e) {
            LOGGER.debug("The declaring class object could not be created");
            // e.printStackTrace();
            // System.exit(1);
            return null;
        } catch (AutofuzzInvocationException e) {
            LOGGER.debug("The arguments passed to the constructor were not well-formed");
            return null;
        } catch (AutofuzzError e) {
            LOGGER.debug("The arguments passed to the constructor were not well-formed");
            return null;
        } catch (NoClassDefFoundError e) { 
            LOGGER.debug("Class could not be initialized");
	    return null;
	}

        // XXX: Need to validate that this below assumption always holds at some point
        // Special case for entry gadgets. For these gadgets we do not need
        // to instantiate the arguments to the gadget but only the object itself
        // so we exit out earlier
        if (node.getType().equals("Trigger")) { 
            LOGGER.debug("Trigger detected, not trying to create arguments to the gadget");
            return objectList;
        }

        return objectList;
        
        // Get the method corresponding to the gadget
        // Method targetMethod = getMethod(targetClass, qualifiedName);
        // // Print method descriptor
        // // LOGGER.debug("Method descriptor" + Type.getMethodDescriptor(targetMethod));

        // 
        // //
        // // Try to create arguments for the parameters taken in by the method
        // // System.out.println("Instantiating arguments");
        // try {
        //     Object[] arguments = Meta.consumeArguments(data, targetMethod, null);
        //     for (int i = 0; i < arguments.length; i++) {
        //         objectList.add(arguments[i]);
        //     }
        //     // LOGGER.debug("Successfully instantiated arguments for the method");
        //     return objectList;
        // } catch (AutofuzzConstructionException e) {
        //     LOGGER.debug("Construction could not complete" + e.getCause());
        //     return objectList;
        // }
    }

    public static Class<?> getClass(String className) throws NoClassDefFoundError, ExceptionInInitializerError {

        // Check if the class can be accessed
        Class<?> targetClass = null;
        try {
            // Explicitly invoking static initializers to trigger some coverage in the code.
            targetClass = Class.forName(className, true, ClassLoader.getSystemClassLoader());
        } catch (ClassNotFoundException e) {
            LOGGER.debug(String.format("Failed to find class %s for autofuzz, please ensure it is contained in the classpath:", className));
            e.printStackTrace();
            System.exit(1);
        }
        return targetClass;
    }

    public static Method getMethod(Class<?> targetClass, String methodSignature) {
        // Identify the method to be invoked by matching the method signature
        LOGGER.debug("Trying to find method:" + methodSignature + " in Class:" + targetClass.getName());
        Method m[] = targetClass.getDeclaredMethods(); 
        Method gadget = null;
        for(int i = 0; i < m.length; i++) {
            // LOGGER.debug(String.format("Orig:%s getQualified:%s getQualifiedFromStatic:%s", m[i].toString(), getQualifiedName(m[i]), methodSignature));
            if (getQualifiedName(m[i]).equals(methodSignature)) {
                // LOGGER.debug("Method found successfully for:" + methodSignature);
                gadget = m[i];
                return gadget;
            }
        }
        return gadget;
    }

    // The method method in java when queried for the name would output
    // public java.lang.Object org.apache.commons.collections.map.LazyMap.get(java.lang.Object)
    // Since we are not interested in the access specifier and the return type we just retrieve the method name along with the parameter. In the instance where the method throws exception then we account for it by ignoring the thrown exceptions while creating the qualified name for comparison
    static String getQualifiedName(Method method) { 
		String[] splited = method.toString().split(" ");
        List splitList = Arrays.asList(splited);
        String id = null;
        if (splitList.contains("throws")) {
                // id = splited[splited.length - 3];
                id = splited[splited.length - 4] + " " + splited[splited.length - 3];
        } else {
                // id = splited[splited.length - 1];
                id = splited[splited.length - 2] + " " + splited[splited.length - 1];
        }
		
        return id;
    }

    // Populates class cache in Meta for valid objects to instantiate when `Class.class` variable is requested
    public static void populateClassCache() {
        LOGGER.debug("Performing reachable node analysis to populate class cache");
        List<GadgetVertexSerializable> reachableNodes = GadgetDB.findReachable();
        Set<Class<?>> uniquePoints = new HashSet<Class<?>>();
        for (GadgetVertexSerializable node: reachableNodes) { 

            try {
                Class<?> member = ObjectFactory.getClass(node.getClsName());
                if (member != null) {
                    LOGGER.debug("Adding class:" + member.getName()); 
                    uniquePoints.add(member);
                }
            } catch(NoClassDefFoundError | ExceptionInInitializerError e) {
                    LOGGER.debug("No class definition exists..skipping");
                    continue;
            }
        }

        // Apart from the reachable nodes, add this class since its necessary to mount attack
        // in case of Rome
        uniquePoints.add(Templates.class);

        // Create an array allocated with the size of the different class variables it needs to hold
        Class<?>[] temp = new Class<?>[uniquePoints.size()];
        temp = uniquePoints.toArray(temp);
        Meta.classCache = temp;
        //
        //
        // Meta.classCache = new Class<?>[2];
		// Meta.classCache[0] = Templates.class;
		// Meta.classCache[1] = ObjectFactory.getClass("com.sun.syndication.feed.impl.ObjectBean");
    }

}
