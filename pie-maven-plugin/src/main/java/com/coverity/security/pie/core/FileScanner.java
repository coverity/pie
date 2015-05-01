package com.coverity.security.pie.core;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.maven.plugin.MojoExecutionException;

public class FileScanner {
    public static URL[] findJars(List<File> roots) throws MojoExecutionException {
        Collection<URL> files = new ArrayList<URL>();
        for (File root : roots) {
            findJars(root, files);
        }
        return files.toArray(new URL[files.size()]);
    }
    private static void findJars(File root, Collection<URL> collection) throws MojoExecutionException {
        for (File file : root.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".jar")) {
                try {
                    collection.add(file.toURI().toURL());
                } catch (MalformedURLException e) {
                    throw new MojoExecutionException("Could not convert file to URL", e);
                }
            }
            if (file.isDirectory()) {
                findJars(file, collection);
            }
        }
    }
}
