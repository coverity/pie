package com.coverity.security.pie.core;

import java.net.URL;
import java.util.Collection;

import org.apache.maven.plugin.MojoExecutionException;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ConfigurationBuilder;

public class JarScanner {
    public static Collection<Class<? extends Policy>> getPolicies(URL[] jars, ClassLoader pluginClassLoader) throws MojoExecutionException {
        Reflections reflections = new Reflections(new ConfigurationBuilder()
            .addClassLoader(pluginClassLoader)
            .setUrls(jars)
            .setScanners(new SubTypesScanner()));
        return reflections.getSubTypesOf(Policy.class);
    }
}
