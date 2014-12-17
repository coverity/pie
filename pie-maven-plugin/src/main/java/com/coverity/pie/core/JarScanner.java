package com.coverity.pie.core;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.maven.plugin.MojoExecutionException;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ConfigurationBuilder;

import com.coverity.pie.core.Policy;

public class JarScanner {
    public static Collection<Class<? extends Policy>> getPolicies(File[] jars) throws MojoExecutionException {
        Collection<URL> urls = new ArrayList<URL>(jars.length);
        try {
            for (File file : jars) {
                urls.add(file.toURI().toURL());
            }
        } catch (MalformedURLException e) {
            throw new MojoExecutionException("Unable to scan plugin JARs.", e);
        }
        
        Reflections reflections = new Reflections(new ConfigurationBuilder()
             .setUrls(urls)
             .setScanners(new SubTypesScanner()));
        return reflections.getSubTypesOf(Policy.class);
    }
}
