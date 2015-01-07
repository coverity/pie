package com.coverity.pie.core;

import io.dropwizard.Bundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import java.net.URLClassLoader;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletContext;

import org.eclipse.jetty.util.component.LifeCycle;
import org.eclipse.jetty.util.component.LifeCycle.Listener;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ConfigurationBuilder;

public class PieBundle implements Bundle {

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
    }

    @Override
    public void run(Environment environment) {
        ServletContext cx = environment.getApplicationContext().getServletContext();
        
        final PieInitializer pieInitializer = new PieInitializer();
        environment.lifecycle().addLifeCycleListener(new Listener() {

            @Override
            public void lifeCycleStopping(LifeCycle event) {
                pieInitializer.contextDestroyed(null);
            }
            
            @Override
            public void lifeCycleStarting(LifeCycle event) {}

            @Override
            public void lifeCycleStarted(LifeCycle event) {}

            @Override
            public void lifeCycleFailure(LifeCycle event, Throwable cause) {}

            @Override
            public void lifeCycleStopped(LifeCycle event) {}
            
        });

        Reflections reflections = new Reflections(new ConfigurationBuilder()
            .setUrls(((URLClassLoader)this.getClass().getClassLoader()).getURLs())
            .setScanners(new SubTypesScanner()));
        final Set<Class<?>> classes = new HashSet<Class<?>>(reflections.getSubTypesOf(PolicyEnforcer.class));
        pieInitializer.doSetup(classes, cx);
    }
    
}
