package analysis; 

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.nio.*;
import org.jgrapht.nio.dot.*;
import org.jgrapht.traverse.*;


public class GadgetVertex {
    final GadgetMethod node;

    public GadgetVertex(GadgetMethod node) {
        this.node = node;
    }

    public String toString() {
        return node.keyString();
    }

    public int hashCode() {
        return toString().hashCode();
    }
   
    public boolean equals(Object o) {
        return (o instanceof GadgetVertex) && (toString().equals(o.toString()));
    }
}
