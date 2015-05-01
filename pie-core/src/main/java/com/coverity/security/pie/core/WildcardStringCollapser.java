package com.coverity.security.pie.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * In implementation of StringCollapser which always collapses facts to a single value.
 */
public class WildcardStringCollapser implements StringCollapser {

    private final String wildcard;

    /**
     * @param wildcard The single value to which all facts will be collapsed.
     */
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

    /**
     * Matching logic with semantics matching the collapsing of this collapser. That is, matcher will always match
     * the matchee if matcher is the wildcard value (as passed to the constructor), and otherwise matches only if
     * matcher.equals(matchee).
     *
     * @param matcher
     * @param matchee
     * @return
     */
    public boolean matches(String matcher, String matchee) {
        if (matcher.equals(wildcard)) {
            return true;
        }
        return matcher.equals(matchee);
    }
}
