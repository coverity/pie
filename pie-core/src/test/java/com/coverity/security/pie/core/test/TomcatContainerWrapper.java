package com.coverity.security.pie.core.test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;

import javax.servlet.*;
import java.net.MalformedURLException;
import java.util.Set;
import java.util.concurrent.Semaphore;

/**
 * A test utility that wraps the embedded Tomcat container. Provides synchronous startup/shutdown methods
 */
public class TomcatContainerWrapper {
    private static class SemaphoreStartupShutdownListener implements ServletContextListener, ServletContainerInitializer {

        private final Semaphore startupSemaphore;
        private final Semaphore shutdownSemaphore;

        public SemaphoreStartupShutdownListener() {
            this.startupSemaphore = new Semaphore(0);
            this.shutdownSemaphore = new Semaphore(0);
        }

        @Override
        public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
            ctx.addListener(this);
        }

        @Override
        public void contextInitialized(ServletContextEvent sce) {
            startupSemaphore.release();
        }

        @Override
        public void contextDestroyed(ServletContextEvent sce) {
            shutdownSemaphore.release();
        }
    }

    private final Tomcat tomcat;
    private final SemaphoreStartupShutdownListener semaphoreStartupShutdownListener;

    public TomcatContainerWrapper() {
        tomcat = new Tomcat();
        tomcat.setPort(18885);
        tomcat.setBaseDir(".");
        tomcat.getHost().setAppBase(".");

        semaphoreStartupShutdownListener = new SemaphoreStartupShutdownListener();
    }

    public TomcatContainerWrapper start() throws ServletException, LifecycleException, InterruptedException, MalformedURLException {
        Context context = tomcat.addWebapp("/myapp", ".");
        context.addServletContainerInitializer(semaphoreStartupShutdownListener, null);
        tomcat.start();
        semaphoreStartupShutdownListener.startupSemaphore.acquire();
        return this;
    }

    public TomcatContainerWrapper stop() throws InterruptedException, LifecycleException {
        tomcat.stop();
        tomcat.destroy();
        semaphoreStartupShutdownListener.shutdownSemaphore.acquire();
        return this;
    }
}
