package com.coverity.pie.util.collapser;

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
    
    private static Map<String, Collection<Void>> nullMap(Collection<String> keys) {
        Map<String, Collection<Void>> result = new HashMap<>(keys.size());
        for (String key : keys) {
            result.put(key, null);
        }
        return result;
    }
    
}
