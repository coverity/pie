package com.coverity.pie.policy.securitymanager.collapse;

import static org.testng.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

public class PropertyPermissionCollapserTest {

    @Test
    public void testSupportedPermisisons() {
        assertEquals(new PropertyPermissionCollapser().supportedPermissions(), Arrays.asList("java.util.PropertyPermission"));
    }
    
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
        
        props = new ArrayList<String>(new PropertyPermissionCollapser().collapse(props));
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
        Collection<String> props = new PropertyPermissionCollapser().collapse(Arrays.asList(
                "a.b",
                "a.c",
                "b.b",
                "b.c"));
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyPermissionCollapser().collapse(Arrays.asList(
                "a.b",
                "*"));
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyPermissionCollapser().collapse(Arrays.asList(
                "*",
                "a.b"));
        assertEquals(props, Arrays.asList("*"));
        
        props = new PropertyPermissionCollapser().collapse(Arrays.asList(
                "*",
                "*"));
        assertEquals(props, Arrays.asList("*"));
    }
    
}
