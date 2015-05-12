package com.coverity.security.pie.policy.securitymanager;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.PolicyConfig;
import org.json.JSONObject;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.SocketPermission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class SocketPermissionsTest {

    @Test
    public void testSocketPermissions() throws IOException {
        /* Test that all 'accept,resolve' permissions get collapsed to a wildcard "*:0" permission, other permissions
           don't have any collapsing behavior, and that the wildcard is respected when new host names are passed to the
           policy.
         */

        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        policy.setPolicyConfig(new PolicyConfig(policy.getName(), new PieConfig()));
        policy.logViolation(null, new SocketPermission("localhost", "accept,resolve"));
        policy.logViolation(null, new SocketPermission("example.com", "accept,resolve"));
        policy.logViolation(null, new SocketPermission("evil.com", "listen,resolve"));
        policy.addViolationsToPolicy();
        policy.collapsePolicy();

        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        JSONObject policyOut = new JSONObject(sw.toString());
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").keySet().size(), 2);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").keySet().contains("accept,resolve"));
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").keySet().contains("listen,resolve"));
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").getJSONObject("accept,resolve").keySet().size(), 1);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").getJSONObject("accept,resolve").keySet().contains("*:0"));
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").getJSONObject("listen,resolve").keySet().size(), 1);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.net.SocketPermission").getJSONObject("listen,resolve").keySet().contains("evil.com"));

        policy.parsePolicy(new StringReader(policyOut.toString()));
        assertTrue(policy.implies(null, new SocketPermission("newhostname.com", "accept,resolve")));
        assertFalse(policy.implies(null, new SocketPermission("newhostname.com", "listen,resolve")));
    }
}
