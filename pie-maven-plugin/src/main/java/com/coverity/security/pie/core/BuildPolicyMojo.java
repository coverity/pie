package com.coverity.security.pie.core;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

import com.coverity.security.pie.web.PieAdminFilter;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.sonatype.aether.RepositorySystemSession;

/**
 * The PIE Maven plugin, which fetches violations from a server and updates local policy files based on those
 * violations.
 */
@Mojo( name = "build-policy", defaultPhase = LifecyclePhase.POST_INTEGRATION_TEST )
public class BuildPolicyMojo extends AbstractMojo
{
    /**
     * Used to extract local repository directory from Maven
     */
    @Parameter( defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    /**
     * The base URL of the server.
     */
    @Parameter( property = "serverUrl", required = true)
    private URL serverUrl;

    /**
     * The path to the PIE configuration.
     */
    @Parameter( property = "pieConfig", required = true)
    private File pieConfig;

    /**
     * A parameter which can be used to only fetch violations starting from a certain timestamp (generally the start
     * of the Maven build).
     */
    @Parameter( property = "startTime", required = false)
    private String startTime;

    /**
     * A parameter which can be used to clear the set of violations from the server.
     */
    @Parameter( defaultValue = "false", property = "clearViolations", required = true)
    private boolean clearViolations;

    /**
     * A parameter which informs the plugin where to look for PIE modules.
     */
    @Parameter( property = "pluginRoots", required = true)
    private List<File> pluginRoots;

    /**
     * Fail the build if there were violations
     */
    @Parameter ( defaultValue = "true", property = "failOnViolations", required = true)
    private boolean failOnViolations;

    public void execute() throws MojoExecutionException, MojoFailureException
    {
        PieConfig pieConfig;
        try {
            pieConfig = new PieConfig(this.pieConfig.toURI().toURL());
        } catch (MalformedURLException e) {
            throw new MojoExecutionException("Invalid pieConfig path.", e);
        }
        
        Long startTimeMill = null;
        if (startTime != null) {
            try {
                startTimeMill = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX").parse(startTime).getTime();
            } catch (ParseException e) {
                throw new MojoExecutionException("Invalid startTime", e);
            }
        }

        if (pluginRoots.size() == 0) {
            pluginRoots.add(new File(repoSession.getLocalRepository().getBasedir().getAbsolutePath() + "/com/coverity/security/pie"));
        }
        
        final URL[] pluginJars = FileScanner.findJars(pluginRoots);
        getLog().info("Found the following PIE jars: " + Arrays.toString(pluginJars));
        final URLClassLoader pluginClassLoader = new URLClassLoader(pluginJars, Policy.class.getClassLoader());
        CloseableHttpClient httpclient = null;
        boolean hadViolations = false;

        try {
            httpclient = HttpClients.createDefault();
            
            for (Class<? extends Policy> clazz : JarScanner.getPolicies(pluginJars, pluginClassLoader)) {
            
                Policy policy;
                try {
                    policy = clazz.newInstance();
                } catch (InstantiationException | IllegalAccessException e) {
                    throw new RuntimeException(e);
                }

                PolicyConfig policyConfig = new PolicyConfig(policy.getName(), pieConfig);
                if (!policyConfig.isEnabled()) {
                    continue;
                }
                policy.setPolicyConfig(policyConfig);
                getLog().info("Creating policy for " + policy.getName());
                
                final URL policyUrl = policyConfig.getPolicyFile();
                if (!policyUrl.getProtocol().equals("file")) {
                    throw new MojoFailureException("Cannot update a non-file policy: " + policyUrl.toString());
                }
                final File policyFile = new File(policyUrl.getPath());
                
                if (policyFile.exists()) {
                    Reader fr = null;
                    try {
                        fr = new InputStreamReader(new FileInputStream(policyFile), StandardCharsets.UTF_8);
                        policy.parsePolicy(fr);
                    } catch (IOException e) {
                        throw new MojoExecutionException("Could not parse policy file: " + policyConfig.getPolicyFile().toString());
                    } finally {
                        IOUtils.closeQuietly(fr);
                    }
                }
                
                URIBuilder uriBuilder;
                try {
                    uriBuilder = new URIBuilder(serverUrl.toString() + PieAdminFilter.ADMIN_FILTER_URI);
                } catch (URISyntaxException e) {
                    throw new MojoExecutionException("Invalid serverUrl.", e);
                }
                
                uriBuilder.addParameter("policyEnforcer", policy.getName());
                if (startTimeMill != null) {
                    uriBuilder.addParameter("startTime", startTimeMill.toString());
                }
                if (clearViolations) {
                    uriBuilder.addParameter("clearViolations", "true");
                }
                
                HttpGet httpGet;
                try {
                    httpGet = new HttpGet(uriBuilder.build());
                } catch (URISyntaxException e) {
                    throw new MojoExecutionException("Invalid serverUrl", e);
                }
                
                CloseableHttpResponse response1 = null;
                InputStream is = null;
                try {
                    response1 = httpclient.execute(httpGet);
                    if (response1.getStatusLine().getStatusCode() != 200) {
                        getLog().error("Got error code from remote server: " + response1.getStatusLine().getReasonPhrase());
                        continue;
                    }
                    
                    long contentLength = response1.getEntity().getContentLength();
                    if (contentLength > 1024*1024*10) {
                        throw new MojoExecutionException("Server response was too large.");
                    }            
                    HttpEntity entity1 = response1.getEntity();
                    is = entity1.getContent();
                    String body = IOUtils.toString(is);
                    IOUtils.closeQuietly(is);

                    final String[] lines = body.split("\n");
                    if (lines.length == 0 || !lines[0].equals("=== PIE REPORT ===")) {
                        getLog().error("Invalid response from PIE server.");
                        continue;
                    }

                    getLog().info("Found " + (lines.length-1) + " violations for " + policy.getName());
                    if (lines.length > 1) {
                        hadViolations = true;
                    }
                    if (pieConfig.isEnabled() && pieConfig.isRegenerateOnShutdown()) {
                        for (int i = 1; i < lines.length; i++) {
                            policy.logViolation(lines[i].split("\t"));
                        }
                        policy.addViolationsToPolicy();
                        if (policyConfig.isCollapseEnabled()) {
                            policy.collapsePolicy();
                        }
                        policy.writePolicy(new OutputStreamWriter(new FileOutputStream(policyFile), StandardCharsets.UTF_8));
                    }
                } catch (IOException e) {
                    throw new MojoExecutionException("Error handling server request.", e);
                } finally {
                    IOUtils.closeQuietly(response1);
                    IOUtils.closeQuietly(is);
                }
            }
        } finally {
            IOUtils.closeQuietly(pluginClassLoader);
            IOUtils.closeQuietly(httpclient);
        }

        if (failOnViolations && hadViolations) {
            throw new MojoFailureException("PIE observed violations on the server.");
        }
    }
}
