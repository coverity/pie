package com.coverity.pie.policy.securitymanager;

import javax.servlet.ServletContext;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.Policy;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.PolicyEnforcer;

public class SecurityManagerPolicyEnforcer implements PolicyEnforcer {
    
    private static final Object MUTEX = new Object();
    private static int startupCount = 0;

    private SecurityManagerPolicy policy;
    private PolicyConfig policyConfig;
    private DynamicJavaPolicy dynamicJavaPolicy;
    

    @Override
    public void init(PieConfig pieConfig) {
        policy = new SecurityManagerPolicy();
        policyConfig = new PolicyConfig(policy.getName(), pieConfig);
        policy.setPolicyConfig(policyConfig);
    }
    
    @Override
    public PolicyConfig getPolicyConfig() {
        return policyConfig;
    }
    
    @Override
    public Policy getPolicy() {
        return policy;
    }
    
    @Override
    public void applyPolicy(ServletContext cx) {
        synchronized(MUTEX) {
            
            if (startupCount > 0) {
                startupCount += 1;
                return;
            }
            
            java.security.Policy parentPolicy = java.security.Policy.getPolicy();
            if (parentPolicy != null && parentPolicy.getClass().getName().equals(DynamicJavaPolicy.class.getName())) {
                // Must have been started up in some other classloader
                throw new IllegalStateException("Having multiple PIE jars in a single container is unsupported. Move PIE from your application WARs to your container's common lib directory.");
            }
            startupCount += 1;
            
            dynamicJavaPolicy = new DynamicJavaPolicy(parentPolicy, policy, policyConfig);
            dynamicJavaPolicy.refresh();
            java.security.Policy.setPolicy(dynamicJavaPolicy);
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

}
