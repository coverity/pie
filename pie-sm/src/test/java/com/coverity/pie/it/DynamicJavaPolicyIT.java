package com.coverity.pie.it;

import static org.easymock.EasyMock.anyObject;
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

import com.coverity.pie.policy.securitymanager.DynamicJavaPolicy;
import com.coverity.pie.policy.securitymanager.PolicyFileUtil;
import com.coverity.pie.policy.securitymanager.SecurityManagerConfig;
import com.coverity.pie.policy.securitymanager.SecurityManagerPolicyBuilder;


public class DynamicJavaPolicyIT {
    @Test
    public void testCertificateValidation() {
        
        // Sanity check certificates
        assertNull(this.getClass().getProtectionDomain().getCodeSource().getCertificates());
        assertNotNull(PolicyFileUtil.class.getProtectionDomain().getCodeSource().getCertificates());
        assertTrue(PolicyFileUtil.class.getProtectionDomain().getCodeSource().getCertificates().length > 0);
        
        // Setup stubs
        final Permission permission = new java.io.FilePermission("/foo", "read");
                
        SecurityManagerConfig securityManagerConfig = createMock(SecurityManagerConfig.class);
        expect(securityManagerConfig.getPolicyPath()).andStubReturn(null);
        expect(securityManagerConfig.isReportOnlyMode()).andStubReturn(false);
        
        SecurityManagerPolicyBuilder policyBuilder = createMock(SecurityManagerPolicyBuilder.class);
        expect(policyBuilder.getConfig()).andStubReturn(securityManagerConfig);
        policyBuilder.registerPolicyViolation(anyObject(StackTraceElement[].class), eq(this.getClass().getProtectionDomain().getCodeSource().getLocation()), same(permission));
        expectLastCall();
        replay(policyBuilder, securityManagerConfig);
        
        // Test
        DynamicJavaPolicy dynamicJavaPolicy = new DynamicJavaPolicy(null, policyBuilder);
        assertFalse(dynamicJavaPolicy.implies(this.getClass().getProtectionDomain(), permission));
        assertTrue(dynamicJavaPolicy.implies(PolicyFileUtil.class.getProtectionDomain(), permission));        
        verify(policyBuilder, securityManagerConfig);
    }
}
