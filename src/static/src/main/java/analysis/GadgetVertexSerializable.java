package analysis; 

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.nio.*;
import org.jgrapht.nio.dot.*;
import org.jgrapht.traverse.*;
import java.io.Serializable;


public class GadgetVertexSerializable implements Serializable {
    final GadgetMethodSerializable node;

    public GadgetVertexSerializable(GadgetMethodSerializable node) {
        this.node = node;
    }

    public String toString() {
        return node.keyString();
    }

    public String getType() {
        return node.getType();
    }

    public String getClsName() {
        return node.getClsName();
    }

    public String getMethodSignature() {
        return node.getMethodSignature();
    }

    public String getQualifiedName() {
        return node.getQualifiedName();
    }


    public int hashCode() {
        return toString().hashCode();
    }
   
    public boolean equals(Object o) {
        return (o instanceof GadgetVertexSerializable) && (toString().equals(o.toString()));
    }
}
