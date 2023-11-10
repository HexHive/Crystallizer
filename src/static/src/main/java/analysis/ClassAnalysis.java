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

// This module is responsible for analyzing a single class
public class ClassAnalysis extends BaseAnalysis {

    String clsName; // Specifies the class to be analyzed
    String sourceDirectory; // Specify the source code directory of the analyzed target 
    String methodName; //  Specify the function to be specified as the entry point for call graph

    public ClassAnalysis(String clsName, String methodName, String sourceDirectory) { 
        this.clsName = clsName;
        this.sourceDirectory = sourceDirectory;
        this.methodName = methodName;
    }

    public void setupSoot() { 
        G.reset();
        Options.v().set_prepend_classpath(true); //-pp
        Options.v().set_whole_program(true); //-w
        Options.v().set_allow_phantom_refs(true);
        // Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_soot_classpath(this.sourceDirectory);
        Options.v().set_process_dir(Collections.singletonList(this.sourceDirectory));
        // SootClass c = Scene.v().forceResolve(this.clsName, SootClass.BODIES);
        // c.setApplicationClass();
        // SootMethod method = c.getMethodByName("sinkGadget");
        // SootMethod method = c.getMethodByName(this.methodName);
        // List entryPoints = new ArrayList();
        // entryPoints.add(method);
        // Scene.v().setEntryPoints(entryPoints);
        Scene.v().loadNecessaryClasses();
        // excludeJDKLib();
        // PackManager.v().runPacks();
    }

    public void runAnalysis() {
        analyzeBody();
        // callGraphAnalysis();
        // buildUniverse();
    }

    public void analyzeBody() {
        SootClass sc = Scene.v().getSootClass(this.clsName);
        SootMethod sm = sc.getMethodByName(this.methodName);
        JimpleBody body = (JimpleBody) sm.retrieveActiveBody();
        // Get the field of interest
        // SootField objField = sc.getField("VulnObj_2 obj");
        // System.out.println(String.format("Field %s", objField));
        // // Iterate through the fields and print their type and name
        // for (SootField field: sc.getFields()) {
        //     System.out.println(String.format("Field Type:%s Name:%s", field.getType(), field.getName()));
        // }

        int c = 0;
        for (Unit u : body.getUnits()) {
            c++;
            Stmt stmt = (Stmt) u;
            System.out.println(String.format("(%d): %s", c, stmt ));
            invokeInfo(stmt);
            // if(stmt.containsFieldRef())
            //     fieldInfo(objField, stmt);
        }
        // System.out.println("This:" + b.getThisLocal());
        // int c = 1;
        // for (Unit u : b.getUnits()) {
        //     System.out.println("(" + c + ")" + u.toString()); 
        //     c += 1;
        // }
        // c = 1;
        // // for (ValueBox vb: b.getUseAndDefBoxes()) {
        // for (ValueBox vb: b.getUseBoxes()) {
        //     System.out.println("(" + c + ")" + vb.toString()); 
        //     System.out.println(String.format("Value:%s", (vb.getValue()).toString())); 
        //     c += 1;
        // }
    }

    public void invokeInfo(Stmt stmt) {
        if(!stmt.containsInvokeExpr())
            return ;
        InvokeExpr invokeExpr = stmt.getInvokeExpr();
        invokeExpr.apply(new AbstractJimpleValueSwitch() {
            @Override
            public void caseStaticInvokeExpr(StaticInvokeExpr v) {
                System.out.println(String.format("    StaticInvokeExpr '%s' from class '%s'", v, v.getType()));
            }

            @Override
            public void caseVirtualInvokeExpr(VirtualInvokeExpr v) {
                System.out.println(String.format("    VirtualInvokeExpr '%s' from local '%s' with type %s", v, v.getBase(), v.getBase().getType()));
                System.out.println("Method:" + v.getMethod().getName());
            }

            @Override
            public void defaultCase(Object v) {
                super.defaultCase(v);
            }
        });
    }

    public void fieldInfo(SootField field, Stmt stmt) {
        FieldRef fieldRef = stmt.getFieldRef();
        fieldRef.apply(new AbstractRefSwitch() {
            @Override
            public void caseStaticFieldRef(StaticFieldRef v) {
                // A static field reference
            }

            @Override
            public void caseInstanceFieldRef(InstanceFieldRef v) {
                if(v.getField().equals(field)){
                    System.out.println(String.format("    Field %s is used through FieldRef '%s'. The base local of FieldRef has type '%s'", field, v, v.getBase().getType()));
                }
            }
        });
    }

    // This tests the callgraph analysis and if it is working correctly
    public void callGraphAnalysis() {
        CallGraph callGraph = Scene.v().getCallGraph();
        System.out.println("Edges:" + callGraph.size());
        SootClass sc = Scene.v().getSootClass(this.clsName);
        SootMethod sm = sc.getMethodByName(this.methodName);
        for(Iterator<Edge> it = callGraph.edgesOutOf(sm); it.hasNext(); ){
            Edge edge = it.next();
            System.out.println("Target:" + (edge.tgt()).getName() + "Class:" + (edge.tgt()).getDeclaringClass());
            System.out.println(String.format("[X] Method '%s' invokes method '%s' through stmt '%s", edge.src(), edge.tgt(), edge.srcUnit()));
        }
    }

    // Identifies triggers/sinks in the class
    public void buildUniverse() {
        SootClass sc = Scene.v().getSootClass(this.clsName);
        SootMethod sm = sc.getMethodByName(this.methodName);
        if (sc.implementsInterface("java.io.Serializable")) {
            for (SootMethod __sm: sc.getMethods()) {
                System.out.println("Method Name:" + __sm.getName());
                if (__sm.getName().equals("readObject")) {
                    System.out.println("Found readobject");
                }
            }
        } else {
            System.out.println("[X] The class is not serializable and cannot be used as a gadget");
        }
    }
}

