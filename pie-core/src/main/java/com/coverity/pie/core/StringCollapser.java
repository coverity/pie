package com.coverity.pie.core;

import java.util.Collection;
import java.util.Map;

public interface StringCollapser {
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input);
}
