package com.coverity.security.pie.dropwizard;

import com.codahale.metrics.annotation.Timed;
import com.codahale.metrics.health.HealthCheck;
import com.coverity.security.pie.core.test.TestPolicyEnforcer;
import com.coverity.security.pie.util.IOUtil;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.eclipse.jetty.server.Server;
import org.testng.annotations.Test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.File;

import static org.testng.Assert.*;

public class PieBundleTest {

    private static class PieDropwizardApplication extends io.dropwizard.Application<Configuration> {

        private Environment environment = null;

        @Override
        public void initialize(Bootstrap<Configuration> bootstrap) {
            bootstrap.addBundle(new PieBundle());
        }

        @Override
        public void run(Configuration configuration, Environment environment) throws Exception {
            this.environment = environment;

            environment.healthChecks().register("helloWorld", new HelloWorldHealthCheck());
            environment.jersey().register(new HelloWorldResource());
        }
    }

    @Path("/hello-world")
    @Produces(MediaType.APPLICATION_JSON)
    private static class HelloWorldResource {
        @GET
        @Timed
        public String sayHello() {
            return "Hello, World!";
        }
    }

    private static class HelloWorldHealthCheck extends HealthCheck {
        @Override
        protected Result check() throws Exception {
            return Result.healthy();
        }
    }

    private static Server startupDropwizard() throws Exception {
        File file = File.createTempFile("dropwizard.yml", null);
        IOUtil.writeFile(file,
                "server:\n" +
                        "  applicationConnectors:\n" +
                        "  - type: http\n" +
                        "    port: 18885\n" +
                        "  adminConnectors:\n" +
                        "  - type: http\n" +
                        "    port: 18886\n");

        PieDropwizardApplication application = new PieDropwizardApplication();
        application.run(new String[]{"server", file.getAbsolutePath()});
        return application.environment.getApplicationContext().getServer();
    }

    @Test
    public void testDropwizardPieBundle() throws Exception {
        IOUtil.writeFile(new File("target/test-classes/pieConfig.properties"), "simple.policyFile = file:target/test-classes/simple.policy");
        final Server server = startupDropwizard();

        try {
            assertNotNull(TestPolicyEnforcer.getInstance());
            assertTrue(TestPolicyEnforcer.getInstance().isApplied());
        } finally {
            server.stop();
            server.destroy();
        }
    }

    @Test
    public void testDropwizardPieBundlePieDisabled() throws Exception {
        IOUtil.writeFile(new File("target/test-classes/pieConfig.properties"), "pie.enabled = false");
        final Server server = startupDropwizard();

        try {
            assertNull(TestPolicyEnforcer.getInstance());
        } finally {
            server.stop();
            server.destroy();
        }
    }
}
