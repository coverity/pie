package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

public class FilePathCollapserTest {
    @Test
    public void testRemoveRedundantPaths() {
        final FilePathCollapser collapser = new FilePathCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "/tmp/a/b/*",
                "/tmp/a/b/c"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/b/*"
                ));
        
        output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "/tmp/a/b/*",
                "/tmp/a/b/c",
                "/tmp/a/c/*"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/-"
                ));
        
    }
    
    @Test
    public void testRemoveDuplicates() {
        final FilePathCollapser collapser = new FilePathCollapser(2);
        
        List<String> output = new ArrayList<String>(collapser.collapse(Arrays.asList(
                "/tmp/a/b/c",
                "/tmp/a/b/c"
                )));
        
        Collections.sort(output);
        Assert.assertEquals(output, Arrays.asList(
                "/tmp/a/b/c"
                ));
    }
}
