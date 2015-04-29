package com.coverity.pie.core;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.List;

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

/**
 * The PIE Maven plugin, which fetches violations from a server and updates local policy files based on those
 * violations.
 */
@Mojo( name = "build-policy", defaultPhase = LifecyclePhase.POST_INTEGRATION_TEST )
public class BuildPolicyMojo extends AbstractMojo
{
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
        
        final URL[] pluginJars = FileScanner.findJars(pluginRoots);
        final URLClassLoader pluginClassLoader = new URLClassLoader(pluginJars, Policy.class.getClassLoader());
        
        CloseableHttpClient httpclient = null;
        try {
            httpclient = HttpClients.createDefault();
            
            for (Class<? extends Policy> clazz : JarScanner.getPolicies(pluginJars, pluginClassLoader)) {
            
                Policy policy;
                try {
                    policy = clazz.newInstance();
                } catch (InstantiationException | IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
                getLog().info("Creating policy for " + policy.getName());
                
                PolicyConfig policyConfig = new PolicyConfig(policy.getName(), pieConfig);
                if (!policyConfig.isEnabled()) {
                    continue;
                }
                policy.setPolicyConfig(policyConfig);
                
                final URL policyUrl = policyConfig.getPolicyFile();
                if (!policyUrl.getProtocol().equals("file")) {
                    throw new MojoFailureException("Cannot update a non-file policy: " + policyUrl.toString());
                }
                final File policyFile = new File(policyUrl.getPath());
                
                if (policyFile.exists()) {
                    FileReader fr = null;
                    try {
                        fr = new FileReader(policyFile);
                        policy.parsePolicy(fr);
                    } catch (IOException e) {
                        throw new MojoExecutionException("Could not parse policy file: " + policyConfig.getPolicyFile().toString());
                    } finally {
                        IOUtils.closeQuietly(fr);
                    }
                }
                
                URIBuilder uriBuilder;
                try {
                    uriBuilder = new URIBuilder(serverUrl.toString() + "/c0bd580ddcb4666b1PIEec61812f3cdf305");
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
                    
                    for (String line : body.split("\n")) {
                        policy.logViolation(line.split("\t"));
                    }
                    policy.addViolationsToPolicy();
                    policy.collapsePolicy();
                    policy.writePolicy(new FileWriter(policyFile));                
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
    }
}
