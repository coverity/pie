package com.coverity.pie.dropwizard;

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

import com.coverity.pie.core.PolicyEnforcer;
import com.coverity.pie.web.PieInitializer;

/**
 * A bundle for Dropwizard support. Include PIE in your Dropwizard application by including PieBundle in your
 * application's initialization method. For example:
 *
 * @Override
 * public void initialize(Bootstrap<HelloWorldConfiguration> bootstrap) {
 *     bootstrap.addBundle(new PieBundle());
 *     ...
 * }
 */
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
