package com.coverity.security.pie.policy.csp.fact;

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class HostFactMetaDataTest {
    @Test
    public void testHostNameMatching() {
        HostFactMetaData hostFactMetaData = HostFactMetaData.getInstance();
        assertTrue(hostFactMetaData.matches("*.foo.bar", "fizz.buzz.foo.bar"));
        assertTrue(hostFactMetaData.matches("*.foo.bar", "buzz.foo.bar"));
        assertFalse(hostFactMetaData.matches("*.foo.bar", "foo.bar"));
        assertFalse(hostFactMetaData.matches("*.foo.bar", "bar"));
        assertFalse(hostFactMetaData.matches("*.foo.bar", "oof.bar"));
        assertFalse(hostFactMetaData.matches("*.foo.bar", "buzz.oof.bar"));
        assertFalse(hostFactMetaData.matches("*.foo.bar", "fizz.buzz.oof.bar"));
    }
}
