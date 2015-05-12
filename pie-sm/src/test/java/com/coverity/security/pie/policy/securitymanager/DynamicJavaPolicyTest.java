package com.coverity.security.pie.policy.securitymanager;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.PolicyConfig;
import org.testng.annotations.Test;

import java.security.Permission;
import java.security.ProtectionDomain;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class DynamicJavaPolicyTest {

    @Test
    public void testSetSecurityManagerDenied() {
        PieConfig pieConfig = new PieConfig();
        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        PolicyConfig policyConfig = new PolicyConfig(policy.getName(), pieConfig);
        DynamicJavaPolicy dynamicJavaPolicy = new DynamicJavaPolicy(null, policy, policyConfig);

        // Sanity check: other permissions are allowed
        assertTrue(dynamicJavaPolicy.implies(String.class.getProtectionDomain(), new RuntimePermission("exitVM")));
        // Test overriding security manager and policy are denied
        assertFalse(dynamicJavaPolicy.implies(String.class.getProtectionDomain(), new RuntimePermission("setSecurityManager")));
        assertFalse(dynamicJavaPolicy.implies(String.class.getProtectionDomain(), new RuntimePermission("setPolicy")));
    }

    @Test
    public void testDeferToParentPolicy() {
        java.security.Policy parentPolicy = new java.security.Policy() {
            @Override
            public boolean implies(ProtectionDomain domain, Permission permission) {
                if (permission.getName().equals("exitVM")) {
                    return true; }
                return false;
            }
        };

        PieConfig pieConfig = new PieConfig();
        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        pieConfig.getProperties().setProperty(policy.getName() + ".isReportOnlyMode", "false");
        PolicyConfig policyConfig = new PolicyConfig(policy.getName(), pieConfig);
        DynamicJavaPolicy dynamicJavaPolicy = new DynamicJavaPolicy(parentPolicy, policy, policyConfig);

        // Sanity check: other permissions are denied
        assertFalse(dynamicJavaPolicy.implies(String.class.getProtectionDomain(), new RuntimePermission("setContextClassLoader")));
        // Test parent permissions respected
        assertTrue(dynamicJavaPolicy.implies(String.class.getProtectionDomain(), new RuntimePermission("exitVM")));
    }
}
