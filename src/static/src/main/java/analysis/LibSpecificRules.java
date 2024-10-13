package analysis;

import soot.*;
import java.util.*;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

// Base class that can be overriden based on the library being analyzed to
// incorporate library specific rules that define which classes are
// instrumented by Soot as well as which ones are excluded from being analyzed
// as a part of the gadget graph
class LibSpecificRules { 

    public static List<String> excludeList = Arrays.asList("jdk.", "java.", "javax.",
        "sun.", "sunw.", "com.sun.", "com.ibm.","com.apple.","apple.awt.", "org.xml", "org.w3c");


    // Specifies the entry points which are to be used for the analysis to
    // kickstart.  In the case of our library-based evaluation we specify entry
    // points as methods that can be jumped into by the known trigger gadget
    // for the said library.
    void initializeEntryPoints() throws Exception {
        throw new Exception("Please create child of this class and specify the entry points you want to put in");
    }

    // Override this method if you need to force set certain application
    // classes in case these are not instrumented by Soot because it
    // considers them part of the JDK. Eg of these are Rome and Click1 where
    // the classes would begin with the prefix `com.sun.syndication` and
    // `javax.` and are ignored by Soot  
    void forceSetApplicationClasses() {
        return;
    }

    // Remove certain things from the exclude list to ensure they are put into
    // the gadget graph.  We need to add edge conditions for certain classes in
    // the case of Rome and Click1 since otherwise the default exclusion list
    // would not add them to the gadget graph
    boolean excludeClass(String clsName) { 
        for (String excluded: excludeList) {
            if (clsName.startsWith(excluded))
                return true;
        }
        return false;
    }
}

class DefaultRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("toString");
        LibAnalysis.entryPoints.add("compare");
        LibAnalysis.entryPoints.add("hashCode");
        LibAnalysis.entryPoints.add("invoke");
    }
}

class ACC31Rules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("toString");
    }

}

class ACC40Rules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("compare");
    }

}

class AspectjweaverRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("hashCode");
    }

}

class BeanshellRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("invoke");
    }

}

class BeanutilsRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("compare");
    }

}

class GroovyRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("invoke");
    }

}

class VaadinRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("toString");
    }

}

class RomeRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("hashCode");
    }

    void forceSetApplicationClasses() {
        for (SootClass sc : Scene.v().getClasses()) {
            if (sc.getName().startsWith("com.sun.syndication")) {
                sc.setApplicationClass();
            } 
        }
    }

    boolean excludeClass(String clsName) {
        if (clsName.startsWith("com.sun.syndication")) {
            return false;
        }
        for (String excluded: excludeList) {
            if (clsName.startsWith(excluded))
                return true;
        }
        return false;
    }
}

class ClickRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("compare");
    }

    void forceSetApplicationClasses() {
        for (SootClass sc : Scene.v().getClasses()) {
            if (sc.getName().startsWith("javax.")) {
                sc.setApplicationClass();
            } 
        }
    }

    boolean excludeClass(String clsName) {
        if (clsName.startsWith("javax.")) {
            return false;
        }
        for (String excluded: excludeList) {
            if (clsName.startsWith(excluded))
                return true;
        }
        return false;
    }
}

class CoherenceRules extends LibSpecificRules {

    void initializeEntryPoints() {
        LibAnalysis.entryPoints.add("toString");
    }

    boolean excludeClass(String clsName) { 
        if (clsName.startsWith("com.tangosol.")) {
            return false;
        }
        return true;
    }

}
