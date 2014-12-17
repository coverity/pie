package com.coverity.pie.core;

import java.util.Collection;
import java.util.Map;

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
