package com.coverity.pie.core;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import com.coverity.pie.policy.csp.CspPolicyEnforcer;
import com.coverity.pie.policy.securitymanager.SecurityManagerPolicyEnforcer;
import com.coverity.pie.util.IOUtil;

public class PieInitializer implements ServletContainerInitializer, ServletContextListener {
    
    private static final List<Class<? extends PolicyEnforcer>> POLICY_ENFORCER_CLASSES = Arrays.<Class<? extends PolicyEnforcer>>asList(
            (Class<? extends PolicyEnforcer>)SecurityManagerPolicyEnforcer.class,
            (Class<? extends PolicyEnforcer>)CspPolicyEnforcer.class
            );
    
    private Map<String, PolicyEnforcer> policyEnforcers = new HashMap<String, PolicyEnforcer>(POLICY_ENFORCER_CLASSES.size());
    private PieConfig pieConfig;
    
    private PolicyGeneratorRunnable policyGeneratorRunnable;
    private Thread policyGeneratorThread;
    
    public void onStartup(Set<Class<?>> c, ServletContext cx) {
        
        pieConfig = new PieConfig();
        if (!pieConfig.isEnabled()) {
            return;
        }
        
        for (Class<? extends PolicyEnforcer> clazz : POLICY_ENFORCER_CLASSES) {
            PolicyEnforcer policyEnforcer;
            try {
                policyEnforcer = clazz.newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
            policyEnforcer.init(pieConfig);
            
            if (policyEnforcer.getPolicyConfig().isEnabled()) {
                
                InputStream is = null;
                try {
                    is = policyEnforcer.getPolicyConfig().getPolicyFile().openStream();
                    policyEnforcer.getPolicy().parsePolicy(new InputStreamReader(is));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                } finally {
                    IOUtil.closeSilently(is);
                }
                
                policyEnforcers.put(policyEnforcer.getPolicy().getName(), policyEnforcer);
                policyEnforcer.applyPolicy(cx);
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
        
        cx.addListener(this);
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
        
        for (PolicyEnforcer policyEnforcer : policyEnforcers.values()) {
            if (pieConfig.isRegenerateOnShutdown()) {
                savePolicy(policyEnforcer);
            }
            policyEnforcer.shutdown();
        }
    }
    
    PolicyEnforcer getPolicyEnforcer(String name) {
        return policyEnforcers.get(name);
    }
    
    private static void savePolicy(PolicyEnforcer policyEnforcer) {
        policyEnforcer.getPolicy().addViolationsToPolicy();
        policyEnforcer.getPolicy().collapsePolicy();
        
        OutputStream os = null;
        try {
            os = new FileOutputStream(policyEnforcer.getPolicyConfig().getPolicyFile().toString());
            policyEnforcer.getPolicy().writePolicy(new OutputStreamWriter(os));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtil.closeSilently(os);
        }
    }
    
    private class PolicyGeneratorRunnable implements Runnable {
        private boolean shuttingDown = false;
        
        @Override
        public void run() {
            while (!shuttingDown) {
                for (PolicyEnforcer policyEnforcer : policyEnforcers.values()) {
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
