package com.coverity.security.pie.util.collapser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;

public class HostnameCollapserTest {
    @Test
    public void testBasicCollapse() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "a.b.c.example.com",
                "d.b.c.example.com",
                "a.b.c.d.example.com",
                "b.b.c.d.example.com",
                "x.y.c.d.example.com",
                "y.y.c.d.example.com"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "*.b.c.example.com",
                "*.c.d.example.com"
                ));
    }
    
    @Test
    public void testRespectSchemeAndPort() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "http://a.b.c.example.com:8080",
                "http://d.b.c.example.com:8080",
                "https://*.d.c.example.com:8080",
                "http://*.e.c.example.com:8081"
                ))).keySet());
        
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
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "http://a.example.com:8080",
                "'none'"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "http://a.example.com:8080"
                ));
        
        output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "'none'"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "'none'"
                ));
    }
    
    @Test
    public void testCollapseQuotedHostnames() {
        final HostnameCollapser collapser = new HostnameCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "example.com",
                "*.net",
                "'self'",
                "'unsafe-inline'",
                "'none'"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "'self'",
                "'unsafe-inline'",
                "*.net",
                "example.com"
                ));
    }
    
    private static Map<String, Collection<Void>> nullMap(Collection<String> keys) {
        Map<String, Collection<Void>> result = new HashMap<>(keys.size());
        for (String key : keys) {
            result.put(key, null);
        }
        return result;
    }
    
}
