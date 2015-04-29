package com.coverity.pie.web;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.HandlesTypes;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.PolicyEnforcer;
import com.coverity.pie.util.IOUtil;

/**
 * An initializer that will automatically be picked up by Servlet 3.0 containers and which instantiates all the PIE
 * modules on the classpath.
 */
@HandlesTypes(PolicyEnforcer.class)
public class PieInitializer implements ServletContainerInitializer, ServletContextListener {
    
    private static final Map<String, PolicyEnforcer> POLICY_ENFORCERS = new HashMap<String, PolicyEnforcer>();

    private PieConfig pieConfig;
    private PolicyGeneratorRunnable policyGeneratorRunnable;
    private Thread policyGeneratorThread;
    
    @Override
    public void onStartup(Set<Class<?>> classes, ServletContext cx) {
        doSetup(classes, cx);
        cx.addListener(this);
    }
    
    public void doSetup(Set<Class<?>> classes, ServletContext cx) {
        
        pieConfig = new PieConfig();
        if (!pieConfig.isEnabled()) {
            return;
        }
        
        for (Class<?> clazz : classes) {
            if (!PolicyEnforcer.class.isAssignableFrom(clazz)) {
                continue;
            }
            
            PolicyEnforcer policyEnforcer;
            try {
                policyEnforcer = (PolicyEnforcer)clazz.newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
            policyEnforcer.init(pieConfig);
            
            String name = policyEnforcer.getPolicy().getName();
            if (POLICY_ENFORCERS.containsKey(name)) {
                policyEnforcer = POLICY_ENFORCERS.get(name);
                if (policyEnforcer.getPolicyConfig().isEnabled()) {
                    policyEnforcer.applyPolicy(cx);
                }
            } else {
                if (policyEnforcer.getPolicyConfig().isEnabled()) {
                    InputStream is = null;
                    try {
                        is = policyEnforcer.getPolicyConfig().getPolicyFile().openStream();
                        policyEnforcer.getPolicy().parsePolicy(new InputStreamReader(is));
                    } catch (FileNotFoundException e) {
                      // Do nothing; policy not created yet  
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    } finally {
                        IOUtil.closeSilently(is);
                    }
                    policyEnforcer.applyPolicy(cx);
                }
                POLICY_ENFORCERS.put(policyEnforcer.getPolicy().getName(), policyEnforcer);
            }
        }
        
        if (pieConfig.isAdminInterfaceEnabled()) {
            PieAdminFilter pieAdminFilter = new PieAdminFilter(this);
            FilterRegistration.Dynamic filterRegistration = cx.addFilter("pieFilter", pieAdminFilter);
            filterRegistration.addMappingForUrlPatterns(null, false, "/*");
        }
        if (pieConfig.isRegenerateOnShutdown()) {
            policyGeneratorRunnable = new PolicyGeneratorRunnable();
            policyGeneratorThread = new Thread(policyGeneratorRunnable);
            policyGeneratorThread.start();
        }
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        if (policyGeneratorThread != null) {
            policyGeneratorRunnable.shuttingDown = true;
            policyGeneratorThread.interrupt();
            while (policyGeneratorThread.isAlive()) {
                try {
                    policyGeneratorThread.join();
                } catch (InterruptedException e) {
                    // Do nothing
                }
            }
        }
        
        for (PolicyEnforcer policyEnforcer : POLICY_ENFORCERS.values()) {
            if (pieConfig.isRegenerateOnShutdown()) {
                savePolicy(policyEnforcer);
            }
            policyEnforcer.shutdown();
        }
    }
    
    PolicyEnforcer getPolicyEnforcer(String name) {
        return POLICY_ENFORCERS.get(name);
    }
    
    private static void savePolicy(PolicyEnforcer policyEnforcer) {
        // Only add violations to the policy if it's in report-only mode
        if (policyEnforcer.getPolicyConfig().isReportOnlyMode()) {
            policyEnforcer.getPolicy().addViolationsToPolicy();
        }
        if (policyEnforcer.getPolicyConfig().isCollapseEnabled()) {
            policyEnforcer.getPolicy().collapsePolicy();
        }
        
        URL policyFile = policyEnforcer.getPolicyConfig().getPolicyFile();
        if (policyFile.getProtocol().equals("file")) {
            OutputStream os = null;
            try {
                os = new FileOutputStream(policyFile.getPath());
                policyEnforcer.getPolicy().writePolicy(new OutputStreamWriter(os));
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                IOUtil.closeSilently(os);
            }
        }
    }
    
    private class PolicyGeneratorRunnable implements Runnable {
        private boolean shuttingDown = false;
        
        @Override
        public void run() {
            while (!shuttingDown) {
                for (PolicyEnforcer policyEnforcer : POLICY_ENFORCERS.values()) {
                    savePolicy(policyEnforcer);
                }
                try {
                    Thread.sleep(30000L);
                } catch (InterruptedException e) {
                    // Do nothing
                }
            }
        }
    }
}
