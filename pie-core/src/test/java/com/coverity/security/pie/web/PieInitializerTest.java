package com.coverity.security.pie.web;

import com.coverity.security.pie.core.test.TestPolicyEnforcer;
import com.coverity.security.pie.core.test.TomcatContainerWrapper;
import com.coverity.security.pie.util.IOUtil;
import org.apache.catalina.LifecycleException;
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;

import static org.testng.Assert.*;

public class PieInitializerTest {
    @Test
    public void testPieDisabled() throws ServletException, LifecycleException, IOException, InterruptedException {
        IOUtil.writeFile(new File("target/test-classes/pieConfig.properties"), "pie.enabled = false");

        TomcatContainerWrapper tomcat = new TomcatContainerWrapper();
        try {
            tomcat.start();
            assertNull(TestPolicyEnforcer.getInstance());
        } finally {
            tomcat.stop();
        }
    }

    @Test
    public void testModuleDisabled() throws ServletException, LifecycleException, IOException, InterruptedException {
        IOUtil.writeFile(new File("target/test-classes/pieConfig.properties"), "simple.isEnabled = false");

        TomcatContainerWrapper tomcat = new TomcatContainerWrapper();
        try {
            tomcat.start();
            assertNotNull(TestPolicyEnforcer.getInstance());
            assertFalse(TestPolicyEnforcer.getInstance().isApplied());
        } finally {
            tomcat.stop();
        }
    }

    @Test
    public void testDefaultSettings() throws ServletException, LifecycleException, IOException, InterruptedException {
        IOUtil.writeFile(new File("target/test-classes/pieConfig.properties"), "simple.policyFile = file:target/test-classes/simple.policy");

        TomcatContainerWrapper tomcat = new TomcatContainerWrapper();
        try {
            tomcat.start();
            assertNotNull(TestPolicyEnforcer.getInstance());
            assertTrue(TestPolicyEnforcer.getInstance().isApplied());
        } finally {
            tomcat.stop();
        }
    }
}
