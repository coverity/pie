package com.coverity.pie.policy.securitymanager.collapse;

import static org.testng.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.coverity.pie.util.collapser.FilePathCollapser;

public class FilePermissionCollapserTest {
    
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
        
        paths = new ArrayList<String>(new FilePathCollapser(2).collapse(nullMap(paths)).keySet());
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
        Collection<String> props = new FilePathCollapser(2).collapse(nullMap(Arrays.asList(
                "/a/b",
                "/a/c",
                "/b/b",
                "/b/c"))).keySet();
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePathCollapser(0).collapse(nullMap(Arrays.asList(
                "/a/b",
                "/-"))).keySet();
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePathCollapser(0).collapse(nullMap(Arrays.asList(
                "/-",
                "/a/b"))).keySet();
        assertEquals(props, Arrays.asList("/-"));
        
        props = new FilePathCollapser(0).collapse(nullMap(Arrays.asList(
                "/-",
                "/-"))).keySet();
        assertEquals(props, Arrays.asList("/-"));
    }
    
    private static Map<String, Collection<Void>> nullMap(Collection<String> keys) {
        Map<String, Collection<Void>> result = new HashMap<>(keys.size());
        for (String key : keys) {
            result.put(key, null);
        }
        return result;
    }
    
}
