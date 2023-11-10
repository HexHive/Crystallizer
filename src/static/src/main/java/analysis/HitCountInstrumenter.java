package analysis;

import soot.*;
import soot.jimple.*;
import soot.util.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import soot.jimple.internal.JIdentityStmt; 
import org.apache.log4j.Logger;

public class HitCountInstrumenter extends BodyTransformer {

    private static final Logger LOGGER = Logger.getLogger(HitCountInstrumenter.class);
    
    // Unique function ID assigned to each method
    static int fnIdx = 0;

    // Setup a mutex to ensure that duplicate function indices are not assigned to different methods
    private ReentrantLock mutex = new ReentrantLock();

    private static HitCountInstrumenter instance = new HitCountInstrumenter();
    private HitCountInstrumenter() {}

    public static HitCountInstrumenter v() { return instance; }

    // The below transform inserts instrumentation that performs the below mentioned actions
    // String idx = "123" // A unique function ID
	// FileWriter fw = new FileWriter("test.txt", true);
	// BufferedWriter writer = new BufferedWriter(fw); 
	// writer.write(str);
	// writer.close();
	protected void internalTransform(Body body, String phase, Map options) {
		// body's method
		SootMethod method = body.getMethod();

        mutex.lock();

		// debugging
		LOGGER.debug("instrumenting method:" + method.getSignature());
        // Get the unit chain
        Chain units = body.getUnits();
        // Get the first insertion point in the unit chain
        Unit insertionPoint = getFirstInsertableUnit(body);

        // Create a local variable that will hold the unique function ID
        Local tmpLocal = Jimple.v().newLocal("fn_idx", ArrayType.v(RefType.v("java.lang.String"), 1));
        body.getLocals().add(tmpLocal);

        // Create local variable for the print stream
        // Local psLocal = Jimple.v().newLocal("psLocal", RefType.v("java.io.PrintStream"));
        // body.getLocals().add(psLocal);
        
        // Create local variable for filewriter
        Local fwLocal = Jimple.v().newLocal("fwLocal", RefType.v("java.io.FileWriter"));
        body.getLocals().add(fwLocal);

        // Create local variable for Bufferedwriter
        Local bwLocal = Jimple.v().newLocal("bwLocal", RefType.v("java.io.BufferedWriter"));
        body.getLocals().add(bwLocal);

        // Create new instance of filewriter object
        Unit fwLocalAssignUnit = Jimple.v().newAssignStmt(fwLocal, Jimple.v().newNewExpr(RefType.v("java.io.FileWriter")));
        units.insertBefore(fwLocalAssignUnit, insertionPoint);

        // Create new instance of bufferedwriter object
        Unit bwLocalAssignUnit = Jimple.v().newAssignStmt(bwLocal, Jimple.v().newNewExpr(RefType.v("java.io.BufferedWriter")));
        units.insertBefore(bwLocalAssignUnit, insertionPoint);

        // Assing to this local variable the prinstream ref
        // Unit psLocalAssignUnit = Jimple.v().newAssignStmt(psLocal, Jimple.v().newStaticFieldRef(Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef()));
        // units.insertBefore(psLocalAssignUnit, insertionPoint);

        // Assign to this local variable the unique function ID
        AssignStmt initID = Jimple.v().newAssignStmt(tmpLocal, StringConstant.v(String.valueOf(fnIdx) + "\n"));
        units.insertBefore(initID, insertionPoint);

        // SootMethod printStringMethod = Scene.v().getMethod("<java.io.PrintStream: void println(java.lang.String)>");
        SootMethod fwConst = Scene.v().getMethod("<java.io.FileWriter: void <init>(java.lang.String,boolean)>");
        SootMethod bwConst = Scene.v().getMethod("<java.io.BufferedWriter: void <init>(java.io.Writer)>");
        // We use methods inherited from Writer because BufferedWriter does not contain this particular write method
        SootMethod bwWrite = Scene.v().getMethod("<java.io.Writer: void write(java.lang.String)>");
        SootMethod bwClose = Scene.v().getMethod("<java.io.BufferedWriter: void close()>");

        // Instantiate the filwriter object with the name of the file and specify append-only mode
        Unit fwConstStmt = Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(fwLocal, fwConst.makeRef(), StringConstant.v("test.txt"), IntConstant.v(1)));  
        units.insertBefore(fwConstStmt, insertionPoint);

        // Instantiate the bufferedwriter object
        Unit bwConstStmt = Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(bwLocal, bwConst.makeRef(), fwLocal));  
        units.insertBefore(bwConstStmt, insertionPoint);

        // Call the write method on the bufferedwriter
        Unit bwWriteStmt = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(bwLocal, bwWrite.makeRef(), tmpLocal));
        units.insertBefore(bwWriteStmt, insertionPoint);

        // Call the close method on the bufferedwriter
        Unit bwCloseStmt = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(bwLocal, bwClose.makeRef()));
        units.insertBefore(bwCloseStmt, insertionPoint);

        // Print the assigned function ID
        // Unit printStmt = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(psLocal, printStringMethod.makeRef(), tmpLocal));
        // units.insertBefore(printStmt, insertionPoint);

        // Store the <clsName, methodName> pair
        // LOGGER.debug("Tostring:" + method.toString());
        // FunctionIDMap.addElement(method.getDeclaringClass().getName(), method.getSubSignature());
        FunctionIDMap.addElement(GadgetMethod.buildQualifiedName(method));
        // Increment the function ID counter
        fnIdx += 1;

        mutex.unlock();

        body.validate();
	}

    // A helper method to find the first unit that we can inject our code before it.
    // There should be no unit before JIdentity statements
    // Source: https://gist.github.com/noidsirius/1ba0493694e79299b74994c8ac70dfb1
    public static Unit getFirstInsertableUnit(Body b){

        Chain<Unit> units = b.getUnits();
        Unit afterLastIdentity = null;
        for(Unit u2 : units){
            if(u2 instanceof JIdentityStmt)
                afterLastIdentity = u2;
            else
                break;
        }
        if(afterLastIdentity == null)
            afterLastIdentity = units.getFirst();
        else
            afterLastIdentity = units.getSuccOf(afterLastIdentity);
        return afterLastIdentity;
    }
}
