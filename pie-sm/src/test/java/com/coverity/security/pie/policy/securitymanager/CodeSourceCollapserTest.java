package com.coverity.security.pie.policy.securitymanager;

import org.testng.annotations.Test;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class CodeSourceCollapserTest {
    @Test
    public void testShorterMatchee() {
        final CodeSourceCollapser collapser = CodeSourceCollapser.getInstance();
        assertFalse(collapser.pathMatches("file:/foo/bar/-", "file:/baz"));
    }

    @Test
    public void testCodeSourceCollapser() {
        final CodeSourceCollapser collapser = CodeSourceCollapser.getInstance();
        Map<String, Collection<Void>> output = collapser.collapse(nullMap(
                "/home/tomcat/webapps/myapp/WEB-INF/classes/com/foo/Foo.class",
                "/home/tomcat/webapps/myapp/WEB-INF/classes/com/bar/Bar.class",
                "/home/tomcat/webapps/myapp/WEB-INF/lib/foo.jar",
                "/home/tomcat/webapps/myapp/WEB-INF/lib/bar.jar"
        ));

        assertEquals(output.size(), 2);
        assertTrue(output.containsKey("/home/tomcat/webapps/myapp/WEB-INF/classes/-"));
        assertTrue(output.containsKey("/home/tomcat/webapps/myapp/WEB-INF/lib/-"));

    }

    private static Map<String, Collection<Void>> nullMap(String ... keys) {
        Map<String, Collection<Void>> map = new HashMap<String, Collection<Void>>();
        for (String key : keys) {
            map.put(key, Collections.<Void>emptySet());
        }
        return map;
    }
}
