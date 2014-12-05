package com.coverity.pie.policy.csp;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.coverity.pie.util.IOUtil;

public class CspPolicyFileUtilTest {
    @Test
    public void testParseFile() throws IOException {
        File file = File.createTempFile("test-policy", null);
        
        final String contents = "/test-url {\n"
            + "    style-src http://localhost:8080 https://localhost:8081;\n"
            + "    script-src http://localhost:8080;\n"
            + "    img-src http://localhost:8080;\n"
            + "};\n"
            + "\n"
            + "/second-url {\n"
            + "    object-src http://host1:8080 https://host2:8081;\n"
            + "    media-src http://host3:8080;\n"
            + "};\n";
        
        IOUtil.writeFile(file, contents);
        CspPolicy policy = CspPolicyFileUtil.parseFile(file.toURI().toURL());
        assertEquals(policy.getPolicyEntries().size(), 2);
        assertEquals(policy.getPolicyEntries().get(0).getUri(), "/test-url");
        assertEquals(policy.getPolicyEntries().get(0).getDirectives().size(), 3);
        assertEquals(policy.getPolicyEntries().get(0).getDirectives().get("style-src"), Arrays.asList("http://localhost:8080", "https://localhost:8081"));
        assertEquals(policy.getPolicyEntries().get(0).getDirectives().get("script-src"), Arrays.asList("http://localhost:8080"));
        assertEquals(policy.getPolicyEntries().get(0).getDirectives().get("img-src"), Arrays.asList("http://localhost:8080"));
        
        assertEquals(policy.getPolicyEntries().get(1).getUri(), "/second-url");
        assertEquals(policy.getPolicyEntries().get(1).getDirectives().size(), 2);
        assertEquals(policy.getPolicyEntries().get(1).getDirectives().get("object-src"), Arrays.asList("http://host1:8080", "https://host2:8081"));
        assertEquals(policy.getPolicyEntries().get(1).getDirectives().get("media-src"), Arrays.asList("http://host3:8080"));
    }

}
