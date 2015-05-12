package com.coverity.security.pie.policy.securitymanager;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.PolicyConfig;
import org.json.JSONObject;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.util.PropertyPermission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class PropertyPermissionsTest {
    @Test
    public void testPropertyPermissions() throws IOException {
        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        policy.setPolicyConfig(new PolicyConfig(policy.getName(), new PieConfig()));
        policy.logViolation(null, new PropertyPermission("bar.baz.foo", "read"));
        policy.logViolation(null, new PropertyPermission("bar.baz.blah", "read"));
        policy.logViolation(null, new PropertyPermission("fizz.buzz.fizbuz", "write"));
        policy.logViolation(null, new PropertyPermission("fizz.buzz.buzzbuzz", "read"));
        policy.addViolationsToPolicy();
        policy.collapsePolicy();

        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        JSONObject policyOut = new JSONObject(sw.toString());
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").keySet().size(), 2);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").keySet().contains("bar.baz.*"));
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").keySet().contains("fizz.buzz.*"));
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").getJSONObject("bar.baz.*").keySet().size(), 1);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").getJSONObject("bar.baz.*").keySet().contains("read"));
        assertEquals(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").getJSONObject("fizz.buzz.*").keySet().size(), 1);
        assertTrue(policyOut.getJSONObject("<null>").getJSONObject("java.util.PropertyPermission").getJSONObject("fizz.buzz.*").keySet().contains("read,write"));
    }
}
