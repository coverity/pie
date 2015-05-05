package com.coverity.security.pie.policy.securitymanager;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.Policy;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.PolicyEnforcer;

import javax.servlet.ServletContext;
import java.io.FilePermission;
import java.security.ProtectionDomain;

/**
 * An implementation of the PolicyEnforcer class for the Java SecurityManager.
 */
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

            /* A pretty weird bug comes up when running in Tomcat (with Tomcat's default security manager) if we don't
            include this. When the JVM needs to load a class while performing a permission check, Tomcat's class
            loader uses the FileSystem API, which does a permission request which (the first time) needs to load the
            relevant PIE classes. The JVM will throw a java.lang.ClassCircularityError in response to having to load a
            class in the middle of loading a class. To avoid this, we make sure the necessary classes are loaded to
            perform FileSystem API checks before loading in the PIE security manager.
             */
            SecurityManagerPolicy fakePolicy = new SecurityManagerPolicy();
            ProtectionDomain fakeProtectionDomain = java.lang.String.class.getProtectionDomain();
            FilePermission fakePermission = new FilePermission("/tmp/foo/bar", "read");
            fakePolicy.logViolation(fakeProtectionDomain.getCodeSource(), fakePermission);
            fakePolicy.addViolationsToPolicy();
            boolean t = new DynamicJavaPolicy(null, fakePolicy, policyConfig).implies(fakeProtectionDomain, fakePermission);
            if (!t) { throw new IllegalStateException("Dummy implies request should have returned true."); }

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
