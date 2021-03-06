package com.coverity.security.pie.core;

import java.util.Collection;
import java.util.Map;

/**
 * Implementation of the StringCollapser interface which does not perform any collapsing.
 */
public class NullStringCollapser implements StringCollapser {

    private static final NullStringCollapser instance = new NullStringCollapser();
    
    private NullStringCollapser() {
    }
    
    public static NullStringCollapser getInstance() {
        return instance;
    }
    
    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        return input;
    }
    
}
