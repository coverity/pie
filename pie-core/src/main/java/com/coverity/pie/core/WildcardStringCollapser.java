package com.coverity.pie.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class WildcardStringCollapser implements StringCollapser {

    private final String wildcard;
    
    public WildcardStringCollapser(String wildcard) {
        this.wildcard = wildcard;
    }
    
    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(1);
        Collection<T> outputCol = new ArrayList<T>();
        output.put(wildcard, outputCol);
        for (Collection<T> collection : input.values()) {
            outputCol.addAll(collection);
        }
        
        return output;
    }

    public boolean matches(String matcher, String matchee) {
        if (matcher.equals(wildcard)) {
            return true;
        }
        return matcher.equals(matchee);
    }
}
