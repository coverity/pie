package com.coverity.security.pie.util.collapser;

import static org.testng.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

public class PropertyCollapserTest {
    
    @Test
    public void testPropertyPermissionCollapser() {
        List<String> props = Arrays.asList(
                "a.b.c.d",
                "a.b.c.e",
                "b.c.d.e",
                "b.c.d.f",
                "b.d.d.e",
                "b.d.d.f",
                "b.e.e.f",
                "c.d.e.f",
                "e.f.g.h",
                "e.f.g.g",
                "e.f.h.h",
                "e.f.h.i");
        
        props = new ArrayList<String>(new PropertyCollapser(2).collapse(nullMap(props)).keySet());
        Collections.sort(props);
        
        assertEquals(props, Arrays.asList(
                "a.b.c.*",
                "b.c.d.*",
                "b.d.d.*",
                "b.e.e.f",
                "c.d.e.f",
                "e.f.*"));
    }
    
    @Test
    public void testCollapseToRoot() {
        Collection<String> props = new PropertyCollapser(2).collapse(nullMap(Arrays.asList(
                "a.b",
                "a.c",
                "b.b",
                "b.c"))).keySet();
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyCollapser(0).collapse(nullMap(Arrays.asList(
                "a.b",
                "*"))).keySet();
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyCollapser(0).collapse(nullMap(Arrays.asList(
                "*",
                "a.b"))).keySet();
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyCollapser(0).collapse(nullMap(Arrays.asList(
                "*",
                "*"))).keySet();
        assertEquals(props, Arrays.asList("*"));
    }
    
    private static Map<String, Collection<Void>> nullMap(Collection<String> keys) {
        Map<String, Collection<Void>> result = new HashMap<>(keys.size());
        for (String key : keys) {
            result.put(key, null);
        }
        return result;
    }
    
}
