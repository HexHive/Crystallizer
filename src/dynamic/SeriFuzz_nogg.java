package com.example; 

// import clojure.*;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.autofuzz.*;

import analysis.GadgetVertexSerializable;
import analysis.GadgetMethodSerializable;

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;
import org.jgrapht.alg.shortestpath.*;


import java.io.*; 
import java.lang.reflect.Constructor;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

// import org.apache.logging.log4j.Logger;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;


public class SeriFuzz { 
    
    // private static final FluentLogger logger = FluentLogger.forEnclosingClass();
    private static final Logger LOGGER = Logger.getLogger(SeriFuzz.class);
    private static String logProperties = "/root/SeriFuzz/src/dynamic/log4j.properties";
    // The targeted library defines how the payload is to be setup 
    // public static String targetLibrary = "vaadin1";
    public static String targetLibrary = "aspectjweaver";
    // public static String targetLibrary = "commons_collections_itw";
    // public static String targetLibrary = "commons_collections_5";
    // public static String targetLibrary = "synthetic_3";

    // This sinkID is used to identify is sink gadget is triggered
    public static List<String> sinkIDs = new ArrayList<String>();

    // This flag identifies if we are running the fuzzer in the dynamic sink identification mode
    public static boolean isSinkIDMode = false;
    // This flag identifiers if we are running the fuzzer in the crash triage mode
    public static boolean isCrashTriageMode = false;

    // Specify the threshold time we put in to get new cov before we deem that the campaign has stalled 
    public static long thresholdTime = 3600;

    // This flag defines if the hooks on sink gadgets acting as sanitizers
    // are to be activated. The reason we have this
    // flag is because we do incremental path validation and in that case its possible
    // for the hooked methods to be triggered during the incremental path validation which
    // would be a false positive
    // public static boolean makeHookActive;
    public static boolean sinkTriggered;


    public static void fuzzerInitialize(String[] args) {
        
        PropertyConfigurator.configure(logProperties);
        LogCrash.makeCrashDir();
        LogCrash.initJDKCrashedPaths();
        if (isSinkIDMode) {
            Meta.isSinkIDMode = true;
            LOGGER.debug("Reinitializing vulnerable sinks found");
            LogCrash.reinitVulnerableSinks();
            return;
        }

        if (isCrashTriageMode) {
            LOGGER.debug("Running the fuzzer in crash triage mode");
            Meta.isCrashTriageMode = true;
        }

        TrackStatistics.sanityCheckSinks();
        TrackStatistics.logInitTimeStamp();
        LogCrash.initCrashID();
        GadgetDB.tagSourcesAndSinks();
        GadgetDB.findAllPaths(); 

        //XXX: This piece of code can be removed if we figure out correctly hooking this method using jazzer
        //mehtod hooks
        if (SeriFuzz.targetLibrary.equals("commons_collections_5")) {
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.LazyMap.get(java.lang.Object)");
        } else if (SeriFuzz.targetLibrary.equals("commons_collections_itw")) {
            // SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.transformKey(java.lang.Object)");
            // SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.transformValue(java.lang.Object)");
            // SeriFuzz.sinkIDs.add("java.util.Map org.apache.commons.collections.map.TransformedMap.transformMap(java.util.Map)");
            // SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.checkSetValue(java.lang.Object)");
            // SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.put(java.lang.Object,java.lang.Object)");
            // SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.put(java.lang.Object,java.lang.Object)");
            // SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.TransformedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastArrayList.<init>(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.getFast()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastArrayList.setFast(boolean)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastArrayList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastArrayList.clear()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastArrayList.clone()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.containsAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastArrayList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastArrayList.hashCode()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastArrayList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.isEmpty()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.FastArrayList.iterator()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastArrayList.lastIndexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.FastArrayList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.FastArrayList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastArrayList.remove(int)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastArrayList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastArrayList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastArrayList.size()");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.FastArrayList.subList(int,int)");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.FastArrayList.toArray()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.FastArrayList.toArray(java.lang.Object[])");
            SeriFuzz.sinkIDs.add("java.lang.String org.apache.commons.collections.FastArrayList.toString()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.set.TransformedSet.decorate(java.util.Set,org.apache.commons.collections.Transformer)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.TransformedSet.<init>(java.util.Set,org.apache.commons.collections.Transformer)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.NullComparator.compare(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.NullComparator.hashCode()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.comparators.NullComparator.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.AllPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.PredicatedList.<init>(java.util.List,org.apache.commons.collections.Predicate)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.PredicatedList.getList()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.PredicatedList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.list.PredicatedList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.PredicatedList.remove(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.PredicatedList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.PredicatedList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.PredicatedList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.PredicatedList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.PredicatedList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.PredicatedList.subList(int,int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.PredicatedList.access$001(org.apache.commons.collections.list.PredicatedList,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.PredicatedList.access$101(org.apache.commons.collections.list.PredicatedList,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.comparators.ComparatorChain.checkChainIntegrity()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.ComparatorChain.compare(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.ComparatorChain.hashCode()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.comparators.ComparatorChain.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.bag.SynchronizedBag$SynchronizedBagSet.<init>(org.apache.commons.collections.bag.SynchronizedBag,java.util.Set,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.SwitchClosure.execute(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.bag.UnmodifiableSortedBag.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableSortedBag.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableSortedBag.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.bag.UnmodifiableSortedBag.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableSortedBag.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.bag.UnmodifiableSortedBag.uniqueSet()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.SynchronizedCollection.<init>(java.util.Collection,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.SynchronizedCollection.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.containsAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.isEmpty()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.collection.SynchronizedCollection.iterator()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.collection.SynchronizedCollection.toArray()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.collection.SynchronizedCollection.toArray(java.lang.Object[])");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.collection.SynchronizedCollection.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.SynchronizedCollection.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.collection.SynchronizedCollection.hashCode()");
            SeriFuzz.sinkIDs.add("java.lang.String org.apache.commons.collections.collection.SynchronizedCollection.toString()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.BlockingBuffer.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.BlockingBuffer.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.ListOrderedSet.clear()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.set.ListOrderedSet.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.ListOrderedSet.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.ListOrderedSet.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.ListOrderedSet.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.set.ListOrderedSet.toArray()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.set.ListOrderedSet.toArray(java.lang.Object[])");
            SeriFuzz.sinkIDs.add("java.lang.String org.apache.commons.collections.set.ListOrderedSet.toString()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.TransformedPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.SynchronizedList.<init>(java.util.List,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.SynchronizedList.getList()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.SynchronizedList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SynchronizedList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.SynchronizedList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.list.SynchronizedList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.SynchronizedList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.SynchronizedList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.SynchronizedList.remove(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.SynchronizedList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.SynchronizedList.subList(int,int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.PredicatedCollection.<init>(java.util.Collection,org.apache.commons.collections.Predicate)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.PredicatedCollection.validate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.PredicatedCollection.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.PredicatedCollection.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.PredicateTransformer.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.WhileClosure.execute(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.FactoryTransformer.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.buffer.UnmodifiableBuffer.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.UnmodifiableBuffer.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.UnmodifiableBuffer.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.buffer.UnmodifiableBuffer.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.UnmodifiableBuffer.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.CircularFifoBuffer.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.getKey()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.getValue()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.setValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.get(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.map.SingletonMap.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.isEmpty()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.containsKey(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.containsValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.SingletonMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.SingletonMap.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.SingletonMap.clear()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.SingletonMap.entrySet()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.SingletonMap.keySet()");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.map.SingletonMap.values()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.isEqualKey(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.isEqualValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.map.SingletonMap.hashCode()");
            SeriFuzz.sinkIDs.add("java.lang.String org.apache.commons.collections.map.SingletonMap.toString()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.NullIsFalsePredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.PrototypeFactory$PrototypeSerializationFactory.<init>(java.io.Serializable)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.PrototypeFactory$PrototypeSerializationFactory.create()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.PrototypeFactory$PrototypeSerializationFactory.<init>(java.io.Serializable,org.apache.commons.collections.functors.PrototypeFactory$1)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.ClosureTransformer.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.TransformedCollection.<init>(java.util.Collection,org.apache.commons.collections.Transformer)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.collection.TransformedCollection.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.collection.TransformedCollection.transform(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.TransformedCollection.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.TransformedCollection.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.FixedSizeSortedMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.FixedSizeSortedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.FixedSizeSortedMap.clear()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.FixedSizeSortedMap.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.FixedSizeSortedMap.entrySet()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.FixedSizeSortedMap.keySet()");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.map.FixedSizeSortedMap.values()");
            SeriFuzz.sinkIDs.add("java.util.SortedMap org.apache.commons.collections.map.PredicatedSortedMap.getSortedMap()");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.map.PredicatedSortedMap.comparator()");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.list.AbstractLinkedList$Node org.apache.commons.collections.list.NodeCachingLinkedList.getNodeFromCache()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.NodeCachingLinkedList.isCacheFull()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.NodeCachingLinkedList.addNodeToCache(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.list.AbstractLinkedList$Node org.apache.commons.collections.list.NodeCachingLinkedList.createNode(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.NodeCachingLinkedList.removeNode(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.NodeCachingLinkedList.removeAllNodes()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableSubList.<init>(org.apache.commons.collections.CursorableLinkedList,int,int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableSubList.clear()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.CursorableSubList.iterator()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableSubList.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.isEmpty()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.CursorableSubList.toArray()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.CursorableSubList.toArray(java.lang.Object[])");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.containsAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableSubList.hashCode()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableSubList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableSubList.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableSubList.get(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableSubList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.CursorableSubList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableSubList.remove(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableSubList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.CursorableSubList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.CursorableSubList.subList(int,int)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.CursorableLinkedList$Listable org.apache.commons.collections.CursorableSubList.insertListable(org.apache.commons.collections.CursorableLinkedList$Listable,org.apache.commons.collections.CursorableLinkedList$Listable,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableSubList.removeListable(org.apache.commons.collections.CursorableLinkedList$Listable)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableSubList.checkForComod()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.TransformerPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.Bag org.apache.commons.collections.bag.PredicatedBag.getBag()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.bag.PredicatedBag.uniqueSet()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.bag.PredicatedBag.getCount(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.SetUniqueList.<init>(java.util.List,java.util.Set)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.SetUniqueList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.SetUniqueList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.SetUniqueList.remove(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.SetUniqueList.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.SetUniqueList.containsAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.list.SetUniqueList.iterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.SetUniqueList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.SetUniqueList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.SetUniqueList.subList(int,int)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.set.UnmodifiableSet.decorate(java.util.Set)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.UnmodifiableSet.<init>(java.util.Set)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.set.UnmodifiableSet.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.UnmodifiableSet.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.UnmodifiableSet.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.UnmodifiableSet.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.set.UnmodifiableSet.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.Bag org.apache.commons.collections.bag.SynchronizedBag.getBag()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.bag.SynchronizedBag.uniqueSet()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.bag.SynchronizedBag.getCount(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.IfClosure.execute(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.AbstractSerializableSetDecorator.<init>(java.util.Set)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.TransformedList.<init>(java.util.List,org.apache.commons.collections.Transformer)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.TransformedList.getList()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.TransformedList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.list.TransformedList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.TransformedList.remove(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.TransformedList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.TransformedList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.TransformedList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.TransformedList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.TransformedList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.TransformedList.subList(int,int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.TransformedList.access$001(org.apache.commons.collections.list.TransformedList,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.TransformedList.access$101(org.apache.commons.collections.list.TransformedList,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.SortedMap org.apache.commons.collections.map.LazySortedMap.getSortedMap()");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.map.LazySortedMap.comparator()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.UnboundedFifoBuffer.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.UnboundedFifoBuffer.isEmpty()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.UnboundedFifoBuffer.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.buffer.UnboundedFifoBuffer.remove()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.UnboundedFifoBuffer.increment(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.UnboundedFifoBuffer.decrement(int)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.buffer.UnboundedFifoBuffer.iterator()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.UnboundedFifoBuffer.access$000(org.apache.commons.collections.buffer.UnboundedFifoBuffer,int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.UnboundedFifoBuffer.access$100(org.apache.commons.collections.buffer.UnboundedFifoBuffer,int)");
            SeriFuzz.sinkIDs.add("java.util.SortedMap org.apache.commons.collections.map.UnmodifiableSortedMap.decorate(java.util.SortedMap)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.UnmodifiableSortedMap.<init>(java.util.SortedMap)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.UnmodifiableSortedMap.clear()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.UnmodifiableSortedMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.UnmodifiableSortedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.UnmodifiableSortedMap.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.UnmodifiableSortedMap.entrySet()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.UnmodifiableSortedMap.keySet()");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.map.UnmodifiableSortedMap.values()");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.map.UnmodifiableSortedMap.comparator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.AndPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.ReverseComparator.compare(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.comparators.ReverseComparator.hashCode()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.comparators.ReverseComparator.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.set.SynchronizedSet.<init>(java.util.Set,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.PredicatedMap.validate(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.PredicatedMap.checkSetValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.PredicatedMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.PredicatedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.transformKey(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.transformValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Map org.apache.commons.collections.map.TransformedMap.transformMap(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.checkSetValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.TransformedMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.TransformedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.util.SortedMap org.apache.commons.collections.map.TransformedSortedMap.getSortedMap()");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.map.TransformedSortedMap.comparator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.NotPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.bidimap.DualTreeBidiMap.comparator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.OrPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.SwitchTransformer.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.list.CursorableLinkedList.iterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.CursorableLinkedList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.CursorableLinkedList.listIterator(int)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.list.CursorableLinkedList$Cursor org.apache.commons.collections.list.CursorableLinkedList.cursor(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.updateNode(org.apache.commons.collections.list.AbstractLinkedList$Node,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.addNode(org.apache.commons.collections.list.AbstractLinkedList$Node,org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.removeNode(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.removeAllNodes()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.registerCursor(org.apache.commons.collections.list.CursorableLinkedList$Cursor)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.broadcastNodeChanged(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.broadcastNodeRemoved(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.CursorableLinkedList.broadcastNodeInserted(org.apache.commons.collections.list.AbstractLinkedList$Node)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.SingletonMap$SingletonValues.<init>(org.apache.commons.collections.map.SingletonMap)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.map.SingletonMap$SingletonValues.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap$SingletonValues.isEmpty()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.map.SingletonMap$SingletonValues.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.SingletonMap$SingletonValues.clear()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.map.SingletonMap$SingletonValues.iterator()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.UnmodifiableOrderedMap.clear()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.UnmodifiableOrderedMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.map.UnmodifiableOrderedMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.UnmodifiableOrderedMap.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.UnmodifiableOrderedMap.entrySet()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.map.UnmodifiableOrderedMap.keySet()");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.map.UnmodifiableOrderedMap.values()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.OnePredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.FixedSizeList.<init>(java.util.List)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.FixedSizeList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.FixedSizeList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.FixedSizeList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.FixedSizeList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.FixedSizeList.clear()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.FixedSizeList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.list.FixedSizeList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.list.FixedSizeList.iterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.FixedSizeList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.FixedSizeList.listIterator(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.FixedSizeList.remove(int)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.FixedSizeList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.FixedSizeList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.FixedSizeList.subList(int,int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.AbstractSerializableListDecorator.<init>(java.util.List)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.UnmodifiableList.decorate(java.util.List)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.UnmodifiableList.<init>(java.util.List)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.list.UnmodifiableList.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.UnmodifiableList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.UnmodifiableList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.UnmodifiableList.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.UnmodifiableList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.UnmodifiableList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.list.UnmodifiableList.listIterator(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.UnmodifiableList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.list.UnmodifiableList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.UnmodifiableList.remove(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.UnmodifiableList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.UnmodifiableList.subList(int,int)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.NonePredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.ForClosure.execute(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.bag.UnmodifiableBag.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableBag.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableBag.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.bag.UnmodifiableBag.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.bag.UnmodifiableBag.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.bag.UnmodifiableBag.uniqueSet()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.NullIsExceptionPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.<init>()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.add(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.addAll(int,java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.contains(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.containsAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableLinkedList.get(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableLinkedList.hashCode()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableLinkedList.indexOf(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.isEmpty()");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.CursorableLinkedList.iterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.CursorableLinkedList.listIterator()");
            SeriFuzz.sinkIDs.add("java.util.ListIterator org.apache.commons.collections.CursorableLinkedList.listIterator(int)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.CursorableLinkedList.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableLinkedList.remove(int)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.CursorableLinkedList.set(int,java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.CursorableLinkedList.size()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.CursorableLinkedList.toArray()");
            SeriFuzz.sinkIDs.add("java.lang.Object[] org.apache.commons.collections.CursorableLinkedList.toArray(java.lang.Object[])");
            SeriFuzz.sinkIDs.add("java.lang.String org.apache.commons.collections.CursorableLinkedList.toString()");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.CursorableLinkedList.subList(int,int)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.CursorableLinkedList$Listable org.apache.commons.collections.CursorableLinkedList.insertListable(org.apache.commons.collections.CursorableLinkedList$Listable,org.apache.commons.collections.CursorableLinkedList$Listable,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.removeListable(org.apache.commons.collections.CursorableLinkedList$Listable)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.CursorableLinkedList$Listable org.apache.commons.collections.CursorableLinkedList.getListableAt(int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.broadcastListableChanged(org.apache.commons.collections.CursorableLinkedList$Listable)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.broadcastListableRemoved(org.apache.commons.collections.CursorableLinkedList$Listable)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.CursorableLinkedList.broadcastListableInserted(org.apache.commons.collections.CursorableLinkedList$Listable)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.TransformerClosure.execute(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.AnyPredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.collection.UnmodifiableBoundedCollection.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableBoundedCollection.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableBoundedCollection.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.UnmodifiableBoundedCollection.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableBoundedCollection.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.list.LazyList.<init>(java.util.List,org.apache.commons.collections.Factory)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.list.LazyList.get(int)");
            SeriFuzz.sinkIDs.add("java.util.List org.apache.commons.collections.list.LazyList.subList(int,int)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastTreeMap.<init>(java.util.SortedMap)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastTreeMap.getFast()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastTreeMap.setFast(boolean)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastTreeMap.get(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastTreeMap.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastTreeMap.isEmpty()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastTreeMap.containsKey(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastTreeMap.containsValue(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Comparator org.apache.commons.collections.FastTreeMap.comparator()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastTreeMap.put(java.lang.Object,java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastTreeMap.putAll(java.util.Map)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastTreeMap.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.FastTreeMap.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.FastTreeMap.equals(java.lang.Object)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.FastTreeMap.hashCode()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.FastTreeMap.clone()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.FastTreeMap.entrySet()");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.FastTreeMap.keySet()");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.FastTreeMap.values()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.functors.ChainedTransformer.transform(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.bag.HashBag.<init>()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.bag.HashBag.<init>(java.util.Collection)");
            SeriFuzz.sinkIDs.add("org.apache.commons.collections.Bag org.apache.commons.collections.bag.TransformedBag.getBag()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.bag.TransformedBag.getCount(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Set org.apache.commons.collections.bag.TransformedBag.uniqueSet()");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.map.LazyMap.get(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.util.Collection org.apache.commons.collections.collection.UnmodifiableCollection.decorate(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.UnmodifiableCollection.<init>(java.util.Collection)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.collection.UnmodifiableCollection.iterator()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableCollection.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableCollection.addAll(java.util.Collection)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.UnmodifiableCollection.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.collection.UnmodifiableCollection.remove(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.collection.AbstractSerializableCollectionDecorator.<init>(java.util.Collection)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.BoundedFifoBuffer.size()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.BoundedFifoBuffer.isEmpty()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.BoundedFifoBuffer.isFull()");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.buffer.BoundedFifoBuffer.clear()");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.buffer.BoundedFifoBuffer.add(java.lang.Object)");
            SeriFuzz.sinkIDs.add("java.lang.Object org.apache.commons.collections.buffer.BoundedFifoBuffer.remove()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.BoundedFifoBuffer.increment(int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.BoundedFifoBuffer.decrement(int)");
            SeriFuzz.sinkIDs.add("java.util.Iterator org.apache.commons.collections.buffer.BoundedFifoBuffer.iterator()");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.BoundedFifoBuffer.access$300(org.apache.commons.collections.buffer.BoundedFifoBuffer,int)");
            SeriFuzz.sinkIDs.add("int org.apache.commons.collections.buffer.BoundedFifoBuffer.access$600(org.apache.commons.collections.buffer.BoundedFifoBuffer,int)");
            SeriFuzz.sinkIDs.add("boolean org.apache.commons.collections.functors.NullIsTruePredicate.evaluate(java.lang.Object)");
            SeriFuzz.sinkIDs.add("void org.apache.commons.collections.functors.ChainedClosure.execute(java.lang.Object)");
        } else if (SeriFuzz.targetLibrary.equals("vaadin1")) {
            SeriFuzz.sinkIDs.add("java.lang.Object com.vaadin.data.util.NestedMethodProperty.getValue()");    
        } else if (SeriFuzz.targetLibrary.equals("aspectjweaver")) {
            SeriFuzz.sinkIDs.add("java.lang.String org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap.writeToPath(java.lang.String,byte[])");
        } else if (SeriFuzz.targetLibrary.equals("synthetic_3")) {
            SeriFuzz.sinkIDs.add("void VulnObj_2.gadget_1()");
        } else {
            LOGGER.info("Unknown target library passed, please put in a trigger gadget handling routine.");
            System.exit(1);
        }

        TrackStatistics.initProgressCounters();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // GadgetDB.showVertices();
        // GadgetDB.printAllPaths();
        // System.exit(1);

        // Operating in the dynamic sink ID mode
        if (isSinkIDMode) {
            boolean didTest = DynamicSinkID.testPotentialSinks(data);
            LOGGER.debug("Test completed");
            return;
        }

        // makeHookActive = false;
        sinkTriggered = false;

        GraphPath<GadgetVertexSerializable, DefaultEdge> candidate = GadgetDB.pickPath();
        TrackStatistics.numVertices = candidate.getVertexList().size(); 

        // Check if we have already found a crash for the corresponding path. We do this by checking if the number of nodes
        // correctly deserialized for a path is equal to the number of vertices in the path. This would mean that we have concretized
        // the entire path successfully and have seen the gadgets being deserialized
        boolean hasCrashedBefore = TrackStatistics.hasCrashedBefore();
        if (hasCrashedBefore) {
            // LOGGER.debug(String.format("Path ID:%d has been crashed before, continuing.", GadgetDB.currentPathID));
            return;
        }

        // Reset counters that keep track of various levels of progress of fuzzer in concretizing a path
        TrackStatistics.resetProgressCounters();

        // boolean didConcretize = GadgetDB.concretizePath(candidate, data);
        boolean didConcretize = GadgetDB.concretizePathNoGG(candidate, data);

        // If for even one of the nodes we were not able to create a concrete
        // object then we error out and try again
        if (!didConcretize) {
            Meta.localCache.clear();
            return;
        }

        LOGGER.debug("==Deserializing payload==");

        // makeHookActive = true;
        //
        // We reset the coverage file since during path validation it may have been populated
        TrackStatistics.resetCoverageFile();

        // If everything worked as expected then the node corresponding to the
        // entry gadget should have the entire payload and that is the only
        // thing we need to serialize 
        List<GadgetVertexSerializable> vertexList = candidate.getVertexList();
        GadgetVertexSerializable entryGadget = vertexList.get(0);
        Class<?> key = ObjectFactory.getClass(entryGadget.getClsName());
        Object payload = (Meta.localCache.get(key));

        // Performing special handling for the trigger gadget if it exists
        // LOGGER.debug("Putting payload inside the trigger gadget");
        Object finalPayload = null;
        try {
            finalPayload = SetupPayload.prepareTrigger(payload); 
        } catch (Exception e) {
            LOGGER.debug("Preparation of trigger gadget failed, exiting");
            e.printStackTrace();
            System.exit(1);
        }

        if (finalPayload == null) {
            LOGGER.debug("Empty payload generated which should not be possible");
            System.exit(1);
        }
        
        // LOGGER.debug(String.format("Final:%s\nInitial:%s" , payload.toString(), finalPayload.toString()));
        entryPoint(finalPayload);

        // Record the covered gadgets during deserialization
        // boolean hasProgressUpdated = TrackStatistics.recordNodeCoverage();
        TrackStatistics.recordCoverage(candidate);
        // TrackStatistics.showCoverage();
        TrackStatistics.writeProgressCounters();
        TrackStatistics.flushProgressCounters();
        TrackStatistics.printProgressCounters(false);
        long elapsedNewCovTime = TrackStatistics.getNewCovElapsedTime();
        if (elapsedNewCovTime > thresholdTime) { 
            // Touch a file to with the timestamp of the last seen new coverage
            // as the signal for when the campaign stalled
            LOGGER.debug(String.format("Campaign has stalled after not finding new cov for:%d", elapsedNewCovTime));
            TrackStatistics.logCoverageStallTimeStamp();
        } else {
            // LOGGER.debug(String.format("Time taken to uncover new coverage:%d", elapsedNewCovTime));
            TrackStatistics.sanityCheckThresholdTime();
        }

        // Check if crash occurred, if so store the payload
        if (SeriFuzz.sinkTriggered) {
            try {
                String pathStr = GadgetDB.getStrPath(candidate);
                LOGGER.debug(String.format("Crash detected for path:%s \n Crash ID is:%d", pathStr, LogCrash.crashID));
                if (TrackStatistics.correctDeserializations < TrackStatistics.numVertices) { 
                    LOGGER.debug("Partial path realized due to routing through jdk");
                    LogCrash.storePayload(payload, true);
                }
                else {
                    LOGGER.debug("Complete path realized");
                    LogCrash.storePayload(payload, false);
                    if (Meta.isCrashTriageMode) {
                        LogCrash.logConstructionSteps();
                        System.exit(1);
                    }
                }
                LogCrash.writeCrashID();
                // System.exit(1);
            } catch (IOException e) {
                LOGGER.debug("Payload storage failed");
            }
        }

        // System.exit(1);
        // // Take the concretized objects from the local cache and create a serialized payload from it
        Meta.localCache.clear();
        if (Meta.isCrashTriageMode) {
            Meta.constructionSteps.clear();
        }
    }

    public static void entryPoint(Object inputObj) {
        try { 
            // Create a serialized object
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(inputObj);
            oos.flush();
            oos.close();
            // We reset the coverage file here since serialization would trigger some gadgets
            // as well which we are not intererested in.
            // XXX: This can potentially be removed if we infer that these gadgets being recorded
            // is not that big of an issue
            TrackStatistics.resetCoverageFile();
            // Deserialize it
            ByteArrayInputStream bis = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object unserObj = (Object)ois.readObject();
            ois.close();
            // Debug mode where we just pass the ground truth payload from commons collections
            // to sanity-check that the gadget chain can indeed be activated
            // FileInputStream fis = new FileInputStream("payload_new.bin");
            // ObjectInputStream ois = new ObjectInputStream(fis);
            // Object unserObj = (Object)ois.readObject();
            // ois.close();
        // } catch (IOException | ClassNotFoundException | ClassCastException ignored) {
        } catch (Exception e) {
            // Debug utility to print where the deserialization is failing
            // e.printStackTrace();
        }
    }


}

