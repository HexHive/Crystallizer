package com.code_intelligence.jazzer.autofuzz;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.File;

public class ClassFiles {
	public static String classAsFile(final Class<?> clazz) {
		return classAsFile(clazz, true);
	}
	
	public static String classAsFile(final Class<?> clazz, boolean suffix) {
		String str;
		if (clazz.getEnclosingClass() == null) {
			str = clazz.getName().replace(".", "/");
		} else {
			str = classAsFile(clazz.getEnclosingClass(), false) + "$" + clazz.getSimpleName();
		}
		if (suffix) {
			str += ".class";			
		}
		return str;  
	}

	public static byte[] classAsBytes(final Class<?> clazz) {
		try {
			final byte[] buffer = new byte[1024];
            // We needed the `Foo` class as a resource stream to manipulate it. However, during
            // testing we realized that because of how jazzer has been compiler we were not able
            // to get the class loader for the foo class because it would default to the bootstrap
            // class because it was defined in the `Meta` class. To circumvent this problem, instead
            // of trying to restructure the fuzzer, we instead crera
            File tmpFile = new File("/root/SeriFuzz/src/dynamic/TemplatesImplHelper.bin");
			final InputStream in = new FileInputStream(tmpFile);
			if (in == null) {
				throw new IOException("couldn't find '" + tmpFile + "'");
			}
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			int len;
			while ((len = in.read(buffer)) != -1) {
				out.write(buffer, 0, len);
			}
			return out.toByteArray();
			// String file = classAsFile(clazz);
            // System.out.println("File name:" + file);
            // // ClassLoader clsLoader = ClassFiles.class.getClassLoader();
            // // System.out.println("Class loader:" + clsLoader);
			// // final InputStream in = clsLoader.getResourceAsStream(file);
			// // final InputStream in = ClassFiles.class.getResourceAsStream(file);
			// if (in == null) {
			// 	throw new IOException("couldn't find '" + file + "'");
			// }
			// final ByteArrayOutputStream out = new ByteArrayOutputStream();
			// int len;
			// while ((len = in.read(buffer)) != -1) {
			// 	out.write(buffer, 0, len);
			// }
			// return out.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
}
