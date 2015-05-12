package com.coverity.security.pie.policy.securitymanager;

import com.coverity.security.pie.core.PieConfig;
import org.testng.annotations.Test;

import javax.servlet.ServletContext;
import java.security.Permission;

import static org.easymock.EasyMock.*;
import static org.testng.Assert.*;

public class SecurityManagerPolicyEnforcerTest {
    @Test
    public void testApplyPolicy() {
        // Setup a stub SecurityManager that will let us clear out the Java policy set later
        assertNull(System.getSecurityManager());
        System.setSecurityManager(new StubSecurityManager());

        try {
            SecurityManagerPolicyEnforcer policyEnforcer = new SecurityManagerPolicyEnforcer();
            policyEnforcer.init(new PieConfig());

            ServletContext servletContext = createStrictMock(ServletContext.class);
            replay(servletContext);
            policyEnforcer.applyPolicy(servletContext);
            verify(servletContext);

            // Verify that the enforcer setup a DynamicJavaPolicy
            assertNotNull(java.security.Policy.getPolicy());
            assertEquals(java.security.Policy.getPolicy().getClass(), DynamicJavaPolicy.class);

            policyEnforcer.shutdown();
        } finally {
            java.security.Policy.setPolicy(null);
            System.setSecurityManager(null);
        }
    }

    private static class StubSecurityManager extends SecurityManager {
        @Override
        public void checkPermission(Permission perm) {
            // Do nothing
        }
    }
}
