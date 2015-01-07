package com.coverity.pie.policy.csp;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;

import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.PolicyConfig;

public class CspPolicyTest {
    @Test
    public void testCollapse() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
        .put("/a/b/c", new JSONObject()
            .put("object-src", new JSONObject()
                .put("b.b.c.example.com", new JSONObject())
                .put("f.b.c.example.com", new JSONObject())
                .put("oof.rab.com", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("a.b.c.example.com", new JSONObject())
                .put("d.b.c.example.com", new JSONObject())
                .put("foo.bar.com", new JSONObject())
            )
        )
        .put("/a/b/d", new JSONObject()
            .put("object-src", new JSONObject()
                .put("j.d.c.example.com", new JSONObject())
                .put("k.d.c.example.com", new JSONObject())
                .put("oof.rab.com", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("h.d.c.example.com", new JSONObject())
                .put("i.d.c.example.com", new JSONObject())
                .put("foo.bar.com", new JSONObject())
            )
        )
        .put("/c/d/e", new JSONObject()
            .put("object-src", new JSONObject()
                .put("1.1", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("2.2", new JSONObject())
            )
        )
        .put("/c/d/f", new JSONObject()
            .put("object-src", new JSONObject()
                .put("3.3", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("4.4", new JSONObject())
            )
        )
        .put("/c/e/g", new JSONObject()
            .put("object-src", new JSONObject()
                .put("5.5", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("6.6", new JSONObject())
            )
        )
        .put("/c/e/h", new JSONObject()
            .put("object-src", new JSONObject()
                .put("7.7", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("8.8", new JSONObject())
            )
        );
        
        CspPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        policy.collapsePolicy();
        
        StringWriter writer = new StringWriter();
        policy.writePolicy(writer);
        jsonPolicy = new JSONObject(writer.toString());
        
        Assert.assertEquals(jsonPolicy.keySet().size(), 2);
        Assert.assertTrue(jsonPolicy.keySet().contains("/a/b/*"));
        Assert.assertTrue(jsonPolicy.keySet().contains("/c/**"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/a/b/*").keySet().size(), 2);
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").keySet().contains("object-src"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").keySet().contains("script-src"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("object-src").keySet().size(), 2);
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("object-src").keySet().contains("*.c.example.com"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("object-src").keySet().contains("oof.rab.com"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("script-src").keySet().size(), 2);
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("script-src").keySet().contains("*.c.example.com"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/b/*").getJSONObject("script-src").keySet().contains("foo.bar.com"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/c/**").keySet().size(), 2);
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").keySet().contains("object-src"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").keySet().contains("script-src"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/c/**").getJSONObject("object-src").keySet().size(), 4);
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("object-src").keySet().contains("1.1"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("object-src").keySet().contains("3.3"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("object-src").keySet().contains("5.5"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("object-src").keySet().contains("7.7"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/c/**").getJSONObject("script-src").keySet().size(), 4);
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("script-src").keySet().contains("2.2"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("script-src").keySet().contains("4.4"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("script-src").keySet().contains("6.6"));
        Assert.assertTrue(jsonPolicy.getJSONObject("/c/**").getJSONObject("script-src").keySet().contains("8.8"));
    }
    
    @Test
    public void testGetPolicyForUri() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
        .put("/a/b/**", new JSONObject()
            .put("default-src", new JSONObject()
                .put("a.b.c.com", new JSONObject())
            )
            .put("script-src", new JSONObject()
                .put("'self'", new JSONObject())
                .put("b.c.com", new JSONObject())
            )
            .put("object-src", new JSONObject()
                .put("c.d.com", new JSONObject())
            )
        )
        .put("/x/y/*", new JSONObject()
            .put("script-src", new JSONObject()
                .put("'unsafe-inline'", new JSONObject())
                .put("'self'", new JSONObject())
                .put("x.y.com", new JSONObject())
            )
            .put("style-src", new JSONObject()
                .put("'self'", new JSONObject())
            )
        );
        
        CspPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        
        Assert.assertEquals(policy.getPolicyForUri("/a/b/c/d"),
                "connect-src a.b.c.com; font-src a.b.c.com; frame-src a.b.c.com; img-src a.b.c.com; media-src a.b.c.com; "
                + "object-src a.b.c.com c.d.com; "
                + "script-src 'self' a.b.c.com b.c.com; "
                + "style-src a.b.c.com");
        
        Assert.assertEquals(policy.getPolicyForUri("/x/y/z"),
                "connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; "
                + "script-src 'self' 'unsafe-inline' x.y.com; "
                + "style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/x/y/z/a"),
                "connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; "
                + "script-src 'none'; style-src 'none'");
    }
    
    @Test
    public void testDontCollapseToRoot() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
        .put("/**", new JSONObject()
            .put("default-src", new JSONObject()
                .put("'self'", new JSONObject())
            )
        )
        .put("/a/b/**", new JSONObject()
            .put("script-src", new JSONObject()
                .put("b.c.com", new JSONObject())
            )
        )
        .put("/a/c/**", new JSONObject()
            .put("script-src", new JSONObject()
                .put("c.c.com", new JSONObject())
            )
        )
        .put("/b/**", new JSONObject()
            .put("script-src", new JSONObject()
                .put("x.y.com", new JSONObject())
            )
        );
        
        CspPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        policy.collapsePolicy();
        
        StringWriter writer = new StringWriter();
        policy.writePolicy(writer);
        jsonPolicy = new JSONObject(writer.toString());
        
        Assert.assertEquals(jsonPolicy.keySet().size(), 3);
        Assert.assertTrue(jsonPolicy.keySet().contains("/**"));
        Assert.assertTrue(jsonPolicy.keySet().contains("/a/**"));
        Assert.assertTrue(jsonPolicy.keySet().contains("/b/**"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/**").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/**").keySet().contains("default-src"));
        Assert.assertEquals(jsonPolicy.getJSONObject("/**").getJSONObject("default-src").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/**").getJSONObject("default-src").keySet().contains("'self'"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/a/**").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/**").keySet().contains("script-src"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/a/**").getJSONObject("script-src").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/a/**").getJSONObject("script-src").keySet().contains("*.c.com"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/b/**").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/b/**").keySet().contains("script-src"));
        
        Assert.assertEquals(jsonPolicy.getJSONObject("/b/**").getJSONObject("script-src").keySet().size(), 1);
        Assert.assertTrue(jsonPolicy.getJSONObject("/b/**").getJSONObject("script-src").keySet().contains("x.y.com"));
    }
    
    @Test
    public void testApplyDefault() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
        .put("/**", new JSONObject()
            .put("default-src", new JSONObject()
                .put("'self'", new JSONObject())
            )
        )
        .put("/a/b/**", new JSONObject()
            .put("script-src", new JSONObject()
                .put("b.c.com", new JSONObject())
            )
        );
        
        CspPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        
        //Assert.assertEquals(policy.getPolicyForUri("/"),
        //        "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self'; style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/foo/bar"),
                "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self'; style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/a"),
                "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self'; style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/a/b"),
                "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self'; style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/a/b/c"),
                "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self' b.c.com; style-src 'self'");
        
        Assert.assertEquals(policy.getPolicyForUri("/a/b/c/d"),
                "connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; script-src 'self' b.c.com; style-src 'self'");
        
    }
    
    @Test
    public void testRootUri() throws URISyntaxException {
        CspPolicy policy = createPolicy();
        policy.logViolation(new URI("/"), "img-src", "'self'");
        policy.logViolation(new URI("/foo"), "img-src", "example.com");
        policy.logViolation(new URI("/a/b"), "img-src", "com.example");
        policy.addViolationsToPolicy();
        
        Assert.assertEquals(policy.getPolicyForUri("/"), 
                "connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'self'; media-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'");
        Assert.assertEquals(policy.getPolicyForUri("/foo"), 
                "connect-src 'none'; font-src 'none'; frame-src 'none'; img-src example.com; media-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'");
        Assert.assertEquals(policy.getPolicyForUri("/a/b"), 
                "connect-src 'none'; font-src 'none'; frame-src 'none'; img-src com.example; media-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'");
    }
    
    private static CspPolicy createPolicy() {
        CspPolicy policy = new CspPolicy();
        policy.setPolicyConfig(new PolicyConfig(policy.getName(), new PieConfig()));
        return policy;
    }
}
