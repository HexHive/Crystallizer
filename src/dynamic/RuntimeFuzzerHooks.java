package com.example;

import java.io.*; 

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import java.lang.Runtime;
import java.lang.Process;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import org.apache.log4j.Logger;

public class RuntimeFuzzerHooks {

  private static final Logger LOGGER = Logger.getLogger(RuntimeFuzzerHooks.class);

  @MethodHook(type = HookType.REPLACE, targetClassName = "VulnObj_2",
  targetMethod = "gadget_1", targetMethodDescriptor = "")
  public static void 
  hookRuntime(MethodHandle handle, Object thisObject, Object[] args, int hookId) {
      if (SeriFuzz.makeHookActive) {
        SeriFuzz.sinkTriggered = true;
        // Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(".exec triggered !"));
        // throw new FuzzerSecurityIssueHigh("Runtime.exec has been called");
      }
      return;
    }    

  @MethodHook(type = HookType.BEFORE, targetClassName = "org.apache.commons.collections.map.LazyMap",
  targetMethod = "get", targetMethodDescriptor = "")
  // targetMethod = "get", targetMethodDescriptor = "(Ljava/lang/Object;)Ljava/lang/Object;")
  public static void 
  hookRuntime1(MethodHandle handle, Object thisObject, Object[] args, int hookId) {
      if (SeriFuzz.makeHookActive) {
        SeriFuzz.sinkTriggered = true;
      }
      return;
    }    

   // @MethodHook(type = HookType.BEFORE, targetClassName = "org.apache.commons.collections.keyvalue.TiedMapEntry",
   // targetMethod = "getValue", targetMethodDescriptor = "")
   // public static void 
   // hookRuntime2(MethodHandle handle, Object thisObject, Object[] args, int hookId) {
   //     LOGGER.info("Sink2 triggered");
   //     if (SeriFuzz.makeHookActive) {
   //       SeriFuzz.sinkTriggered = true;
   //       // Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(".exec triggered !"));
   //       // throw new FuzzerSecurityIssueHigh("Runtime.exec has been called");
   //     }
   //     return;
   //   }    
}

