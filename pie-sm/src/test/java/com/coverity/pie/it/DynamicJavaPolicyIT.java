package com.coverity.pie.it;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.security.Permission;

import org.testng.annotations.Test;

import com.coverity.pie.core.Policy;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.policy.securitymanager.DynamicJavaPolicy;
import com.coverity.pie.policy.securitymanager.SecurityManagerPolicy;


public class DynamicJavaPolicyIT {
    @Test
    public void testCertificateValidation() {
        
        // Sanity check certificates
        assertNull(this.getClass().getProtectionDomain().getCodeSource().getCertificates());
        assertNotNull(Policy.class.getProtectionDomain().getCodeSource().getCertificates());
        assertTrue(Policy.class.getProtectionDomain().getCodeSource().getCertificates().length > 0);
        
        // Setup stubs
        final Permission permission = new java.io.FilePermission("/foo", "read");
                
        PolicyConfig policyConfig = createMock(PolicyConfig.class);
        expect(policyConfig.isReportOnlyMode()).andStubReturn(false);
        
        SecurityManagerPolicy policy = createMock(SecurityManagerPolicy.class);
        expect(policy.implies(eq(this.getClass().getProtectionDomain().getCodeSource()), same(permission))).andStubReturn(false);
        policy.logViolation(eq(this.getClass().getProtectionDomain().getCodeSource()), same(permission));
        expectLastCall();
        replay(policy, policyConfig);
        
        // Test
        DynamicJavaPolicy dynamicJavaPolicy = new DynamicJavaPolicy(null, policy, policyConfig);
        assertFalse(dynamicJavaPolicy.implies(this.getClass().getProtectionDomain(), permission));
        assertTrue(dynamicJavaPolicy.implies(Policy.class.getProtectionDomain(), permission));        
        verify(policy, policyConfig);
    }
}
