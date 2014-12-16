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

public class UriCspDirectiveCollapserTest {
    @Test
    public void testBasicCollapse() {
        final UriCspDirectiveCollapser collapser = new UriCspDirectiveCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap(
                "/a/b/c", "/a/b/d", "/c/d/e", "/c/d/f", "/c/g/h", "/c/g/j")).keySet());
        Collections.sort(output);
                
        Assert.assertEquals(output, Arrays.asList("/a/b/*", "/c/**"));
    }
    
    @Test
    public void testDoNotCollapseToRoot() {
        final UriCspDirectiveCollapser collapser = new UriCspDirectiveCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(nullMap("/**", "/a/a", "/a/b")).keySet());
        Collections.sort(output);
                
        Assert.assertEquals(output, Arrays.asList("/**", "/a/*"));
    }

    private static Map<String, Collection<Void>> nullMap(String ... keys) {
        Map<String, Collection<Void>> result = new HashMap<>(keys.length);
        for (String key : keys) {
            result.put(key, null);
        }
        return result;
    }
}
