package com.coverity.security.pie.policy.securitymanager;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.Permission;
import java.security.cert.Certificate;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.util.IOUtil;
import org.json.JSONObject;
import org.testng.annotations.Test;

public class SecurityManagerPolicyTest {
    
    @Test
    public void testJavaPolicyParser() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        final String contents =
                  "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/commons-fileupload-1.0.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/lucene-1.4.1.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/search\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/search/*\", \"delete,read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete,write\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/pebble-2.6.4.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/-\", \"delete,read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/*\", \"delete,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/images/*\", \"write\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-security-core-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-security-web-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-web-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/xercesImpl-2.8.1.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/2013/11/21/1385056620000.xml\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/2014/11/24/*\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/pages/1416865080967/1416865080967.xml\", \"read\";\n"
                + "    permission java.io.FilePermission \"/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/xerces.properties\", \"read\";\n"
                + "};\n";
                
        
        IOUtil.writeFile(file, contents);
        SecurityManagerPolicy policy = createPolicy();
        policy.parseJavaPolicy(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
        policy.writeJavaPolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
        assertEquals(IOUtil.readFile(file), contents);
    }

    @Test
    public void testJavaPolicyWriter() throws IOException {
        SecurityManagerPolicy policy = createPolicy();
        policy.logViolation(null, new MyPermission("foo", "bar"));
        policy.logViolation(null, new MyPermission("foo", null));
        policy.logViolation(null, new MyPermission("foo", "fizz"));
        policy.logViolation(null, new MyPermission("goo", "bar"));
        policy.logViolation(null, new MyPermission("goo", null));
        policy.logViolation(null, new MyPermission("goo", "fizz"));
        policy.addViolationsToPolicy();

        StringWriter sw = new StringWriter();
        policy.writeJavaPolicy(sw);
        assertEquals(sw.toString(),
                "grant codeBase \"<null>\" {\n" +
                "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"foo\", \"bar\";\n" +
                "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"foo\", \"fizz\";\n" +
                "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"goo\", \"bar\";\n" +
                "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"goo\", \"fizz\";\n" +
                "};\n");
    }
    
    @Test
    public void testCollapsePerms() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
            .put("file:/tmp/foo.jar", new JSONObject()
                .put("java.io.FilePermission", new JSONObject()
                    .put("/tmp/foo/bar/baz.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo/bar/bing.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo/blarg.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo2/bar/baz.txt", new JSONObject().put("read,write", new JSONObject()))
                    .put("/tmp/foo2/bar/blarg.txt", new JSONObject().put("read,write", new JSONObject()))
                    .put("/tmp/foo4/bar/baz.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo4/bar/bing.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo4/bar2/baz.txt", new JSONObject().put("read", new JSONObject()))
                    .put("/tmp/foo4/bar2/bing.txt", new JSONObject().put("read", new JSONObject()))
                )
            );
        
        SecurityManagerPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        policy.collapsePolicy();
        
        StringWriter writer = new StringWriter();
        policy.writePolicy(writer);
        jsonPolicy = new JSONObject(writer.toString());
        
        JSONObject fileGrants = jsonPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission");
        assertEquals(fileGrants.keySet().size(), 4);
        
        assertTrue(fileGrants.keySet().contains("/tmp/foo/bar/*"));
        assertEquals(fileGrants.getJSONObject("/tmp/foo/bar/*").keySet().size(), 1);
        assertTrue(fileGrants.getJSONObject("/tmp/foo/bar/*").keySet().contains("read"));
        
        assertTrue(fileGrants.keySet().contains("/tmp/foo/blarg.txt"));
        assertEquals(fileGrants.getJSONObject("/tmp/foo/blarg.txt").keySet().size(), 1);
        assertTrue(fileGrants.getJSONObject("/tmp/foo/blarg.txt").keySet().contains("read"));
        
        assertTrue(fileGrants.keySet().contains("/tmp/foo2/bar/*"));
        assertEquals(fileGrants.getJSONObject("/tmp/foo2/bar/*").keySet().size(), 1);
        assertTrue(fileGrants.getJSONObject("/tmp/foo2/bar/*").keySet().contains("read,write"));
        
        assertTrue(fileGrants.keySet().contains("/tmp/foo4/-"));
        assertEquals(fileGrants.getJSONObject("/tmp/foo4/-").keySet().size(), 1);
        assertTrue(fileGrants.getJSONObject("/tmp/foo4/-").keySet().contains("read"));
    }
    
    @Test
    public void testUnifyPolicy() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        IOUtil.writeFile(file, "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/blarg.txt\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo2/bar/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo4/-\", \"read\";\n"
                + "};\n");
        
        SecurityManagerPolicy policy = createPolicy();
        policy.parseJavaPolicy(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
        
        java.security.cert.Certificate[] certs = null;
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new FilePermission("/tmp/foo/bar/baz.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new FilePermission("/tmp/foo/bar/bing.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/foo.jar"), certs), new FilePermission("/tmp/foo/blarg.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/foo.jar"), certs), new FilePermission("/tmp/foo3/bar/baz.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/foo.jar"), certs), new FilePermission("/tmp/foo4/bar/bing.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/foo.jar"), certs), new FilePermission("/tmp/foo2/bar/baz.txt", "read"));
        
        policy.addViolationsToPolicy();
        policy.collapsePolicy();
        policy.writeJavaPolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
        
        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/bar.jar\" {\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/blarg.txt\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo2/bar/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo3/bar/baz.txt\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo4/-\", \"read\";\n"
                + "};\n");
    }
    
    @Test
    public void testSimplePolicy() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        IOUtil.writeFile(file, 
                  "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/commons-fileupload-1.0.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/lucene-1.4.1.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/search\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/search/*\", \"delete,read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete,write\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/pebble-2.6.4.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/-\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/2014/11/24/1416865020000.xml\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/files/blog_shellshock.txt\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/images/Image080.jpg\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/pages.lock\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/indexes/search/*\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/pages/1416865080967.lock\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/theme.bak\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/theme.bak/*\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/theme.bak/images/*\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/theme/aaa\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/*\", \"write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/aaa\", \"delete\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/images/*\", \"write\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-security-core-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-security-web-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/spring-web-3.0.3.RELEASE.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read\";\n"
                + "};\n"
                + "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/xercesImpl-2.8.1.jar\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/2013/11/21/1385056620000.xml\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/2014/11/24/*\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/pages/1416865080967/1416865080967.xml\", \"read\";\n"
                + "    permission java.io.FilePermission \"/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/xerces.properties\", \"read\";\n"
                + "};\n");

        SecurityManagerPolicy policy = createPolicy();
        policy.parseJavaPolicy(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
        policy.collapsePolicy();
        policy.writeJavaPolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));

        assertEquals(IOUtil.readFile(file),
            "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/-\" {\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/blogs/default/-\", \"delete,read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/pebble/realm/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp\", \"read\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/temp/*\", \"delete,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/*\", \"delete,write\";\n"
                + "    permission java.io.FilePermission \"/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/themes/user-default/images/*\", \"write\";\n"
                + "    permission java.io.FilePermission \"/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/xerces.properties\", \"read\";\n"
                + "};\n");
    }
    
    @Test
    public void testOtherPerms() throws IOException {
        
        SecurityManagerPolicy policy = createPolicy();
        
        java.security.cert.Certificate[] certs = null;
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new FilePermission("/tmp/foo/bar/baz.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new FilePermission("/tmp/foo/bar/bing.txt", "read"));
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("tacos", null));
        policy.logViolation(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("burritos", "churros"));
        policy.addViolationsToPolicy();
        policy.collapsePolicy();

        assertTrue(policy.implies(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("tacos", null)));
        assertTrue(policy.implies(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("burritos", null)));
        assertTrue(policy.implies(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("burritos", "churros")));
        assertFalse(policy.implies(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("burritos", "hamburgers")));
        assertFalse(policy.implies(new CodeSource(new URL("file:/tmp/bar.jar"), certs), new MyPermission("churros", null)));
        
        File file = File.createTempFile("test-policy", null);
        policy.writeJavaPolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
        
        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/bar.jar\" {\n"
                + "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"burritos\", \"churros\";\n"
                + "    permission com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission \"tacos\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n");
    }
    
    private static class MyPermission extends Permission {
        private static final long serialVersionUID = 1L;

        private final String actions;

        public MyPermission(String name, String actions) {
            super(name);
            this.actions = actions;
        }

        @Override
        public boolean implies(Permission permission) {
            return false;
        }

        @Override
        public String getActions() {
            return actions;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null || !(obj instanceof MyPermission)) {
                return false;
            }
            return getName().equals(((MyPermission)obj).getName());
        }

        @Override
        public int hashCode() {
            return getName().hashCode();
        }
        
    }
    
    @Test
    public void testParseNoActions() throws IOException {
        
        File file = File.createTempFile("test-policy", null);
        IOUtil.writeFile(file,
                "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission com.acme.MyPermission \"burritos\";\n"
                + "    permission com.acme.MyPermission \"tacos\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n");
        
        SecurityManagerPolicy policy = createPolicy();
        policy.parseJavaPolicy(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
        policy.writeJavaPolicy(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));

        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission com.acme.MyPermission \"burritos\";\n"
                + "    permission com.acme.MyPermission \"tacos\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n");
    }
    
    @Test
    public void testImplies() throws IOException {
        JSONObject jsonPolicy = new JSONObject()
        .put("file:/tmp/foo.jar", new JSONObject()
            .put("java.io.FilePermission", new JSONObject()
                .put("/tmp/foo/bar/baz.txt", new JSONObject().put("read", new JSONObject()))
            )
        );
    
        SecurityManagerPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader(jsonPolicy.toString()));
        
        final CodeSource codeSource = new CodeSource(new URL("file:/tmp/foo.jar"), (java.security.cert.Certificate[])null);
        assertTrue(policy.implies(codeSource, new FilePermission("/tmp/foo/bar/baz.txt", "read")));
        assertFalse(policy.implies(codeSource, new FilePermission("/tmp/foo/bar/baz.txt", "write")));
        assertFalse(policy.implies(codeSource, new FilePermission("/tmp/foo/bar/bar.txt", "read")));
        
        final CodeSource codeSource2 = new CodeSource(new URL("file:/tmp/bar.jar"), (java.security.cert.Certificate[])null);
        assertFalse(policy.implies(codeSource2, new FilePermission("/tmp/foo/bar/baz.txt", "read")));
    }
    
    @Test
    public void testConfigCollapseThreshold() throws IOException {
        File file = File.createTempFile("test-config", null);
        IOUtil.writeFile(file,
                "pie.enabled = true\n"
                + "securityManager.enabled = true\n"
                + "securityManager.FilePermission.collapseThreshold = 4");
        
        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        policy.setPolicyConfig(new PolicyConfig(policy.getName(), new PieConfig(file.toURI().toURL())));
        
        final CodeSource codeSource = new CodeSource(new URL("file:/tmp/foo.jar"), new Certificate[0]); 
        policy.logViolation(codeSource, new FilePermission("/a/b/c", "read"));
        policy.logViolation(codeSource, new FilePermission("/a/b/d", "read"));
        policy.logViolation(codeSource, new FilePermission("/a/b/e", "read"));
        policy.logViolation(codeSource, new FilePermission("/x/b/c", "read"));
        policy.logViolation(codeSource, new FilePermission("/x/b/d", "read"));
        policy.logViolation(codeSource, new FilePermission("/x/b/e", "read"));
        policy.logViolation(codeSource, new FilePermission("/x/b/f", "read"));
        
        policy.addViolationsToPolicy();
        policy.collapsePolicy();
        
        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        JSONObject outPolicy = new JSONObject(sw.toString());
        
        assertEquals(outPolicy.length(), 1);
        assertTrue(outPolicy.has("file:/tmp/foo.jar"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").has("java.io.FilePermission"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission").length(), 4);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission").has("/a/b/c"));
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission").has("/a/b/d"));
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission").has("/a/b/e"));
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("java.io.FilePermission").has("/x/b/*"));
    }

    @Test
    public void testParseMBeanPermissions() throws IOException {
        SecurityManagerPolicy policy = createPolicy();

        final CodeSource codeSource = new CodeSource(new URL("file:/tmp/foo.jar"), new Certificate[0]);
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-", "registerMBean"));
        policy.addViolationsToPolicy();

        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        JSONObject outPolicy = new JSONObject(sw.toString());

        assertEquals(outPolicy.length(), 1);
        assertTrue(outPolicy.has("file:/tmp/foo.jar"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").has("javax.management.MBeanPermission"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").getJSONObject("*:*").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").getJSONObject("*:*").has("registerMBean"));

        assertTrue(policy.implies(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:foo=bar]", "registerMBean")));

        // Parse with empty ObjectName instead of missing ObjectName
        policy = createPolicy();
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[]", "registerMBean"));
        policy.addViolationsToPolicy();

        sw = new StringWriter();
        policy.writePolicy(sw);
        outPolicy = new JSONObject(sw.toString());

        assertEquals(outPolicy.length(), 1);
        assertTrue(outPolicy.has("file:/tmp/foo.jar"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").has("javax.management.MBeanPermission"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").getJSONObject("*:*").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("-").getJSONObject("*:*").has("registerMBean"));

        assertTrue(policy.implies(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:foo=bar]", "registerMBean")));

        // Parse with missing member
        policy = createPolicy();
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter", "registerMBean"));
        policy.addViolationsToPolicy();

        sw = new StringWriter();
        policy.writePolicy(sw);
        outPolicy = new JSONObject(sw.toString());

        assertEquals(outPolicy.length(), 1);
        assertTrue(outPolicy.has("file:/tmp/foo.jar"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").has("javax.management.MBeanPermission"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission").getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("*").length(), 1);
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("*").getJSONObject("*:*").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").getJSONObject("javax.management.MBeanPermission")
                .getJSONObject("com.codahale.metrics.JmxReporter$JmxMeter").getJSONObject("*").getJSONObject("*:*").has("registerMBean"));

        assertTrue(policy.implies(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#fizzbuzz[metrics:foo=bar]", "registerMBean")));
    }
    
    @Test
    public void testMBeanPermissionFacts() throws IOException {
        SecurityManagerPolicy policy = createPolicy();
        
        final CodeSource codeSource = new CodeSource(new URL("file:/tmp/foo.jar"), new Certificate[0]);
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=com.coverity.caas.app.resources.webapp.GitHubInvitationResource.list.exceptions]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=com.coverity.caas.app.resources.webapp.GitHubInvitationResource.list]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=com.coverity.caas.app.resources.webapp.WebTokensResource.generate.exceptions]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=com.coverity.caas.app.resources.webapp.WebTokensResource.generate]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=io.dropwizard.jetty.MutableServletContextHandler.1xx-responses]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=io.dropwizard.jetty.MutableServletContextHandler.2xx-responses]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=io.dropwizard.jetty.MutableServletContextHandler.3xx-responses]", "registerMBean"));
        policy.logViolation(codeSource, new javax.management.MBeanPermission("com.codahale.metrics.JmxReporter$JmxMeter#-[metrics:name=io.dropwizard.jetty.MutableServletContextHandler.4xx-responses]", "registerMBean"));
        policy.addViolationsToPolicy();
        policy.collapsePolicy();
        
        StringWriter sw = new StringWriter();
        policy.writePolicy(sw);
        JSONObject outPolicy = new JSONObject(sw.toString());
        
        assertEquals(outPolicy.length(), 1);
        assertTrue(outPolicy.has("file:/tmp/foo.jar"));
        assertEquals(outPolicy.getJSONObject("file:/tmp/foo.jar").length(), 1);
        assertTrue(outPolicy.getJSONObject("file:/tmp/foo.jar").has("javax.management.MBeanPermission"));
        // FIXME: Verify collapse/matching of jmx permissions
    }

    @Test
    public void testCodeSourceMatching() throws IOException {
        SecurityManagerPolicy policy = createPolicy();
        policy.parsePolicy(new StringReader("{\n" +
                "   \"file:/WEB-INF/classes/com/foo/*\": {\n" +
                "      \"com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission\": { \"abc\": {} }\n" +
                "   },\n" +
                "   \"file:/WEB-INF/classes/com/bar/*\": {\n" +
                "      \"com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission\": { \"def\": {} }\n" +
                "   },\n" +
                "   \"file:/WEB-INF/lib/-\": {\n" +
                "      \"com.coverity.security.pie.policy.securitymanager.SecurityManagerPolicyTest$MyPermission\": { \"ghi\": {} }\n" +
                "   }\n" +
                "}"));

        assertTrue(policy.implies(new CodeSource(new URL("file:/WEB-INF/classes/com/foo/Foo.class"), (Certificate[]) null), new MyPermission("abc", null)));
        assertTrue(policy.implies(new CodeSource(new URL("file:/WEB-INF/classes/com/foo/Bar.class"), (Certificate[]) null), new MyPermission("abc", null)));
        assertFalse(policy.implies(new CodeSource(new URL("file:/WEB-INF/classes/com/foo/bar/Foo.class"), (Certificate[]) null), new MyPermission("abc", null)));
        assertFalse(policy.implies(new CodeSource(new URL("file:/WEB-INF/classes/com/bar/Foo.class"), (Certificate[]) null), new MyPermission("abc", null)));
        assertTrue(policy.implies(new CodeSource(new URL("file:/WEB-INF/classes/com/bar/Foo.class"), (Certificate[]) null), new MyPermission("def", null)));
        assertTrue(policy.implies(new CodeSource(new URL("file:/WEB-INF/lib/foo.jar!com/foo/Foo.class"), (Certificate[]) null), new MyPermission("ghi", null)));
        assertFalse(policy.implies(new CodeSource(new URL("file:/WEB-INF/lib/foo.jar!com/foo/Foo.class"), (Certificate[]) null), new MyPermission("abc", null)));
        assertFalse(policy.implies(new CodeSource(new URL("file:/WEB-INF/lib/foo.jar!com/foo/Foo.class"), (Certificate[]) null), new MyPermission("def", null)));
    }
    
    private static SecurityManagerPolicy createPolicy() {
        SecurityManagerPolicy policy = new SecurityManagerPolicy();
        policy.setPolicyConfig(new PolicyConfig(policy.getName(), new PieConfig()));
        return policy;
    }
}
