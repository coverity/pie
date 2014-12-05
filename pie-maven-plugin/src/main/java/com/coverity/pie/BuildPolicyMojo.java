package com.coverity.pie;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;

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
import com.coverity.pie.core.PolicyBuilder;
import com.coverity.pie.policy.csp.CspPolicyBuilder;
import com.coverity.pie.policy.securitymanager.SecurityManagerPolicyBuilder;

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

    private static final Collection<Class<? extends PolicyBuilder>> POLICY_BUILDER_CLASSES = Arrays.<Class<? extends PolicyBuilder>>asList(
            SecurityManagerPolicyBuilder.class,
            CspPolicyBuilder.class
            );
            
    
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
        
        for (Class<? extends PolicyBuilder> clazz : POLICY_BUILDER_CLASSES) {
        
            PolicyBuilder policyBuilder;
            try {
                policyBuilder = clazz.newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
            policyBuilder.init(pieConfig);
            if (!policyBuilder.isEnabled()) {
                continue;
            }
            
            URIBuilder uriBuilder;
            try {
                uriBuilder = new URIBuilder(serverUrl.toString() + "/c0bd580ddcb4666b1PIEec61812f3cdf305");
            } catch (URISyntaxException e) {
                throw new MojoExecutionException("Invalid serverUrl.", e);
            }
            
            uriBuilder.addParameter("policyEnforcer", policyBuilder.getName());
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
            try {
                response1 = httpclient.execute(httpGet);
                long contentLength = response1.getEntity().getContentLength();
                if (contentLength > 1024*1024*10) {
                    throw new MojoExecutionException("Server response was too large.");
                }            
                HttpEntity entity1 = response1.getEntity();
                InputStream is = entity1.getContent();
                String body = IOUtils.toString(is);
                IOUtils.closeQuietly(is);
                
                policyBuilder.registerPolicyViolations(body);
                policyBuilder.savePolicy();
                
            } catch (IOException e) {
                throw new MojoExecutionException("Error handling server request.", e);
            } finally {
                IOUtils.closeQuietly(response1);
            }
        }
        
        IOUtils.closeQuietly(httpclient);
    }
}
