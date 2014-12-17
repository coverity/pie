package com.coverity.pie.core;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

public class FileScanner {
    public static File[] findJars(File root) {
        Collection<File> files = new ArrayList<File>();
        findJars(root, files);
        return files.toArray(new File[files.size()]);
    }
    private static void findJars(File root, Collection<File> collection) {
        for (File file : root.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".jar")) {
                collection.add(file);
            }
            if (file.isDirectory()) {
                findJars(file, collection);
            }
        }
    }
}
