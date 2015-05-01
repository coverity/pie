package com.coverity.security.pie.policy.securitymanager;

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;

public class CodeSourceCollapserTest {
    @Test
    public void testShorterMatchee() {
        final CodeSourceCollapser collapser = CodeSourceCollapser.getInstance();
        assertFalse(collapser.pathMatches("file:/foo/bar/-", "file:/baz"));
    }
}
