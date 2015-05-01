package com.coverity.security.pie.util.collapser;

import static org.testng.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;

public class FilePathCollapserTest {
    @Test
    public void testRemoveRedundantPaths() {
        final FilePathCollapser collapser = new FilePathCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "/tmp/a/b/*",
                "/tmp/a/b/c"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/b/*"
                ));
        
        output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "/tmp/a/b/*",
                "/tmp/a/b/c",
                "/tmp/a/c/*"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/-"
                ));
        
    }
    
    @Test
    public void testRemoveDuplicates() {
        final FilePathCollapser collapser = new FilePathCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(Arrays.asList(
                "/tmp/a/b/c",
                "/tmp/a/b/c"
                ))).keySet());
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/b/c"
                ));
    }
    
    @Test
    public void testFilePathCollapser() {
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
