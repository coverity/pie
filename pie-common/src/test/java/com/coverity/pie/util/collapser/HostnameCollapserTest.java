package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

public class HostnameCollapserTest {
    @Test
    public void testBasicCollapse() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "a.b.c.example.com",
                "d.b.c.example.com",
                "a.b.c.d.example.com",
                "b.b.c.d.example.com",
                "x.y.c.d.example.com",
                "y.y.c.d.example.com"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "*.b.c.example.com",
                "*.c.d.example.com"
                ));
    }
    
    @Test
    public void testRespectSchemeAndPort() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "http://a.b.c.example.com:8080",
                "http://d.b.c.example.com:8080",
                "https://*.d.c.example.com:8080",
                "http://*.e.c.example.com:8081"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "http://*.b.c.example.com:8080",
                "http://*.e.c.example.com:8081",
                "https://*.d.c.example.com:8080"
                ));
    }
    
    @Test
    public void testCollapseNoneHostname() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "http://a.example.com:8080",
                "'none'"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "http://a.example.com:8080"
                ));
        
        output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "'none'"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "'none'"
                ));
    }
    
    @Test
    public void testCollapseQuotedHostnames() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "example.com",
                "*.net",
                "'self'",
                "'unsafe-inline'",
                "'none'"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "'self'",
                "'unsafe-inline'",
                "*.net",
                "example.com"
                ));
    }
}
