package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.StringUtil;

public class PropertyCollapser extends AbstractPathCollapser implements StringCollapser {

    public PropertyCollapser(int collapseThreshold) {
        super("*", "*", collapseThreshold, 0);
    }

    public Collection<String> collapse(Collection<String> input) {
        Map<PathName, Collection<Void>> inputMap = new HashMap<PathName, Collection<Void>>(input.size());
        for (String property : input) {
            inputMap.put(new PathName(property.split("\\."), null), null);
        }
        Map<PathName, Collection<Void>> outputMap = collapsePaths(inputMap);
        Collection<String> output = new ArrayList<String>(outputMap.size());
        for (PathName pathName : outputMap.keySet()) {
            output.add(StringUtil.join(".", pathName.getPathComponents()));
        }
        return output;
    }

    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        Map<PathName, Collection<T>> inputMap = new HashMap<PathName, Collection<T>>(input.size());
        for (Map.Entry<String, Collection<T>> entry : input.entrySet()) {
            inputMap.put(new PathName(entry.getKey().split("\\."), null), entry.getValue());
        }
        Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(outputMap.size());
        for (Map.Entry<PathName, Collection<T>> entry : outputMap.entrySet()) {
            output.put(StringUtil.join(".", entry.getKey().getPathComponents()), entry.getValue());
        }
        return output;
    }
    
    public boolean pathNameMatches(String matcher, String matchee) {
        return pathNameMatches(new PathName(matcher.split("\\."), null), new PathName(matchee.split("\\."), null));
    }
}
