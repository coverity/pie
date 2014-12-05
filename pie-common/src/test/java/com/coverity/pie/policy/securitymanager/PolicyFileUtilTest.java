package com.coverity.pie.policy.securitymanager;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.coverity.pie.policy.securitymanager.PolicyFileUtil;
import com.coverity.pie.policy.securitymanager.collapse.Collapser;
import com.coverity.pie.policy.securitymanager.collapse.FilePermissionCollapser;
import com.coverity.pie.policy.securitymanager.collapse.PropertyPermissionCollapser;
import com.coverity.pie.util.IOUtil;

public class PolicyFileUtilTest {
    
    private Collection<Collapser> collapsers;
    
    @BeforeClass
    public void setup() {
        collapsers = Arrays.<Collapser>asList(
                new FilePermissionCollapser(),
                new PropertyPermissionCollapser()
                );
    }
    
    @Test
    public void testEmptyPolicy() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), false, Collections.<PermissionRequest>emptyList(), collapsers);
        assertEquals(IOUtil.readFile(file), "");
    }
    
    @Test
    public void testEmptyDatastore() throws IOException {
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
                + "};\n";
                
        
        IOUtil.writeFile(file, contents);
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), false, Collections.<PermissionRequest>emptyList(), collapsers);
        assertEquals(IOUtil.readFile(file), contents);
    }
    
    @Test
    public void testCollapsePerms() throws IOException {
        List<PermissionRequest> permissionRequests = Arrays.asList(
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/bing.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/blarg.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo2/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo2/bar/blarg.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo2/bar/baz.txt", "write"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo2/bar/blarg.txt", "write"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo4/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo4/bar/bing.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo4/bar2/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo4/bar2/bing.txt", "read")
                );
        
        File file = File.createTempFile("test-policy", null);
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), false, permissionRequests, collapsers);
        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/blarg.txt\", \"read\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo2/bar/*\", \"read,write\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo4/-\", \"read\";\n"
                + "};\n");
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
        
        List<PermissionRequest> permissionRequests = Arrays.asList(
                new PermissionRequest(0L, "file:/tmp/bar.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/bar.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/bing.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/blarg.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo4/bar/bing.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo3/bar/baz.txt", "read")
                );
        
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), false, permissionRequests, collapsers);
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
                
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), true, Collections.<PermissionRequest>emptyList(), collapsers);
        assertEquals(IOUtil.readFile(file), 
                "grant codeBase \"file:/home/ihaken/tomcats/pebble/webapps/pebble-2.6.4/WEB-INF/lib/-\" {\n"
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
                + "    permission java.io.FilePermission \"/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/xerces.properties\", \"read\";\n"
                + "};\n");
    }
    
    @Test
    public void testOtherPerms() throws IOException {
        List<PermissionRequest> permissionRequests = Arrays.asList(
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/baz.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "java.io.FilePermission", "/tmp/foo/bar/bing.txt", "read"),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "com.acme.MyPermission", "tacos", null),
                new PermissionRequest(0L, "file:/tmp/foo.jar", "com.foo.Bar", "com.acme.MyPermission", "burritos", null)
                );
        
        File file = File.createTempFile("test-policy", null);
        PolicyFileUtil.buildPolicyFile(file.toURI().toURL(), false, permissionRequests, collapsers);
        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission com.acme.MyPermission \"burritos\";\n"
                + "    permission com.acme.MyPermission \"tacos\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n");
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
        
        PolicyFileUtil.buildPolicyFile(new File("/home/ihaken/tomcats/pebble/lib/piePolicy.policy").toURI().toURL(), false, Collections.<PermissionRequest>emptyList(), collapsers);

        assertEquals(IOUtil.readFile(file),
                "grant codeBase \"file:/tmp/foo.jar\" {\n"
                + "    permission com.acme.MyPermission \"burritos\";\n"
                + "    permission com.acme.MyPermission \"tacos\";\n"
                + "    permission java.io.FilePermission \"/tmp/foo/bar/*\", \"read\";\n"
                + "};\n");
    }
}
