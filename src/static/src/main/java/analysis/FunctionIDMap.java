package analysis; 

import java.util.*;
import java.io.*;
import org.apache.log4j.Logger;

// Data structure that maintains the unique ID assigned to each
// <clsName.methodSignature> pair The unique ID is implicitly maintained as index
// assigned to each pair.
//
public class FunctionIDMap {

    private static final Logger LOGGER = Logger.getLogger(FunctionIDMap.class);

    static List<String> idMap = new ArrayList<>();

    static void addElement(String candidate) {
        // See if the method that we are seeing has been instrumented before
        for (Iterator<String> iterator = idMap.iterator(); iterator.hasNext();) { 
            String element = iterator.next();
            // Double check that this pair does not already exist. This should never happen
            // and if it does we error out here
            if (element.equals(candidate)) {
                LOGGER.info("The element:" + element + "has duplicated entry...exiting");
                System.exit(1);
            }
        }
        idMap.add(candidate);
    }

    // Flushes the map to disk
    static void flushMap() {
        try {
            FileOutputStream fos = new FileOutputStream("fnIDList.store");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(idMap);
            oos.close();
            fos.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    // Reads the serialized map from disk and sanity check that the elements read in were the same as that were dumped
    static void readMap() {
        try {
            FileInputStream fin = new FileInputStream("fnIDList.store");
            ObjectInputStream oin = new ObjectInputStream(fin);
            List<String> readList = (List<String>) oin.readObject();
            Iterator<String> it1 = readList.iterator();
            Iterator<String> it2 = idMap.iterator();
            while (it1.hasNext() && it2.hasNext()) {
                String item1 = it1.next();
                String item2 = it2.next();
                assert (item1.equals(item2)) : "The elements read and dumped in were different, exiting";
            }
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
    }

    // Check that the no duplicated IDs were not assigned to different
    // functions This can be done by checking the assertion that the current
    // value of HitCountInstrumenter.fnIdx is equal to the number of functions
    // that were instrumented. If there was a race condition while performing
    // the instrumentation then the previous specified assertion would fail.
    public static void sanityCheckIDs() {
        LOGGER.debug(String.format("[sanity] idMap size:%d fnIdx:%d", idMap.size(), HitCountInstrumenter.fnIdx));
        assert (idMap.size() == HitCountInstrumenter.fnIdx) : "There are potentially duplicated function ID's assigned which can affect how concretization progress is quantified, please re-check.";
    } 
                           
}

