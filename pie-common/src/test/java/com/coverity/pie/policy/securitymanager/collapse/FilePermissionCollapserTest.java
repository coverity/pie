package com.coverity.pie.policy.securitymanager.collapse;

import static org.testng.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

public class FilePermissionCollapserTest {

    @Test
    public void testSupportedPermisisons() {
        assertEquals(new FilePermissionCollapser().supportedPermissions(), Arrays.asList("java.io.FilePermission"));
    }
    
    @Test
    public void testFilePermissionCollapser() {
        List<String> paths = Arrays.asList(
                "/a/b/c/d",
                "/a/b/c/e",
                "/b/c/d/e",
                "/b/c/d/f",
                "/b/d/d/e",
                "/b/d/d/f",
                "/b/e/e/f",
                "/c/d/e/f",
                "/e/f/g/h",
                "/e/f/g/g",
                "/e/f/h/h",
                "/e/f/h/i");
        
        paths = new ArrayList<String>(new FilePermissionCollapser().collapse(paths));
        Collections.sort(paths);
        
        assertEquals(paths, Arrays.asList(
                "/a/b/c/*",
                "/b/c/d/*",
                "/b/d/d/*",
                "/b/e/e/f",
                "/c/d/e/f",
                "/e/f/-"));
    }
    
    @Test
    public void testCollapseToRoot() {
        Collection<String> props = new FilePermissionCollapser().collapse(Arrays.asList(
                "/a/b",
                "/a/c",
                "/b/b",
                "/b/c"));
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePermissionCollapser().collapse(Arrays.asList(
                "/a/b",
                "/-"));
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePermissionCollapser().collapse(Arrays.asList(
                "/-",
                "/a/b"));
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePermissionCollapser().collapse(Arrays.asList(
                "/-",
                "/-"));
        assertEquals(props, Arrays.asList("/-"));
    }
    
}
