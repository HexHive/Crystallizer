package analysis;

import java.util.*;
import java.util.ArrayList;
import java.util.List;
import java.io.Serializable;

public class GadgetMethodSerializable implements Serializable {

    final String clsName; 
    final String methodSignature; 
	final String qualifiedName; // The method name constructed to allow for comparison against what is output by method method in java 
    final String type; // Type of gadget [Source/Sink/Chain]

    // We setup the unique key as <clsName: methodName(methodParameters)>
    public String keyString() {
        return this.methodSignature;
    }

    GadgetMethodSerializable(String clsName, String methodSignature, String type, String qualifiedName) {
        this.clsName = clsName;
        this.methodSignature = methodSignature;
        this.qualifiedName = qualifiedName;
        this.type = type;
    }

    String getMethodSignature() {
        return this.methodSignature;
    }

    String getClsName() {
        return this.clsName;
    }

    String getType() {
        return this.type;
    }

    String getQualifiedName() {
        return this.qualifiedName;
    }

}
