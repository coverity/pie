package com.coverity.pie.core;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.Policy;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.util.IOUtil;

@Mojo( name = "build-policy", defaultPhase = LifecyclePhase.POST_INTEGRATION_TEST )
public class BuildPolicyMojo extends AbstractMojo
{
    @Parameter( property = "serverUrl", required = true)
    private URL serverUrl;
    
    @Parameter( property = "pieConfig", required = true)
    private File pieConfig;
    
    @Parameter( property = "startTime", required = false)
    private String startTime;
    
    @Parameter( defaultValue = "false", property = "clearViolations", required = true)
    private boolean clearViolations;
    
    @Parameter( property = "pluginsRoot", required = true)
    private File pluginsRoot;

    
    public void execute() throws MojoExecutionException
    {
        PieConfig pieConfig;
        try {
            pieConfig = new PieConfig(this.pieConfig.toURI().toURL());
        } catch (MalformedURLException e) {
            throw new MojoExecutionException("Invalid pieConfig path.", e);
        }
        
        CloseableHttpClient httpclient = HttpClients.createDefault();
        
        Long startTimeMill = null;
        if (startTime != null) {
            try {
                startTimeMill = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX").parse(startTime).getTime();
            } catch (ParseException e) {
                throw new MojoExecutionException("Invalid startTime", e);
            }
        }
        
        for (Class<? extends Policy> clazz : JarScanner.getPolicies(FileScanner.findJars(pluginsRoot))) {
        
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
            InputStream is = null;
            try {
                is = policyConfig.getPolicyFile().openStream();
                policy.parsePolicy(new InputStreamReader(is));                
            } catch (IOException e) {
                throw new MojoExecutionException("Could not parse policy file: " + policyConfig.getPolicyFile().toString());
            } finally {
                IOUtil.closeSilently(is);
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
            is = null;
            try {
                response1 = httpclient.execute(httpGet);
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
                policy.writePolicy(new FileWriter(policyConfig.getPolicyFile().toString()));                
            } catch (IOException e) {
                throw new MojoExecutionException("Error handling server request.", e);
            } finally {
                IOUtils.closeQuietly(response1);
                IOUtils.closeQuietly(is);
            }
        }
        
        IOUtils.closeQuietly(httpclient);
    }
}
