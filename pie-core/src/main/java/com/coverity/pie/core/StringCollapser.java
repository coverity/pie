package com.coverity.pie.core;

import java.util.Collection;
import java.util.Map;

/**
 * An abstract interface for simplifying/collapsing a security policy.
 */
public interface StringCollapser {
    /**
     * Collapses a security policy according to the concrete implementation's rules. It takes a map from facts to their
     * children, and returns a collapsed version of that map. For example, given the map:
     * {
     *   A => {'X', 'Y'},
     *   B => {'Z'}
     * }
     *
     * If the implementation determines that the facts A and B should be collapsed to fact C, then this would return
     * {
     *   C => {'X', 'Y', 'Z'}
     * }
     *
     * @param input A map from facts to a collection of child facts.
     * @param <T> The type of the child facts; irrelevant to the internal procedure of collapsing.
     * @return The collapsed map of facts to their children.
     */
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input);
}
