package com.coverity.pie.policy.securitymanager;

import java.security.Policy;

import javax.servlet.ServletContext;

import com.coverity.pie.core.AbstractPolicyEnforcer;
import com.coverity.pie.core.PolicyBuilder;
import com.coverity.pie.policy.securitymanager.SecurityManagerPolicyBuilder;

public class SecurityManagerPolicyEnforcer extends AbstractPolicyEnforcer {
    
    private static final Object MUTEX = new Object();
    private static int startupCount = 0;

    private final SecurityManagerPolicyBuilder policyBuilder = new SecurityManagerPolicyBuilder();
    private DynamicJavaPolicy dynamicJavaPolicy;
    
    @Override
    protected PolicyBuilder getPolicyBuilder() {
        return policyBuilder;
    }
    
    @Override
    public void applyPolicy(ServletContext cx) {
        synchronized(MUTEX) {
            
            if (startupCount > 0) {
                startupCount += 1;
                return;
            }
            
            Policy policy = Policy.getPolicy();
            if (policy != null && policy.getClass().getName().equals(DynamicJavaPolicy.class.getName())) {
                // Must have been started up in some other classloader
                throw new IllegalStateException("Having multiple PIE jars in a single container is unsupported.");
            }
            startupCount += 1;
            
            dynamicJavaPolicy = new DynamicJavaPolicy(policy, policyBuilder);
            dynamicJavaPolicy.refresh();
            Policy.setPolicy(dynamicJavaPolicy);
            if (System.getSecurityManager() == null) {
                System.setSecurityManager(new SecurityManager());
            }
        }
    }

    @Override
    public void shutdown() {
        synchronized(MUTEX) {
            startupCount -= 1;
        }
    }

    @Override
    public void refreshPolicy() {
        dynamicJavaPolicy.refresh();
    }

}
