package com.coverity.pie.util.collapser;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.StringUtil;

public class FilePathCollapser extends AbstractPathCollapser implements StringCollapser {

    public FilePathCollapser(int collapseThreshold) {
        super("*", "-", collapseThreshold, 0);
    }

    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        Map<PathName, Collection<T>> inputMap = new HashMap<PathName, Collection<T>>(input.size());
        for (Map.Entry<String, Collection<T>> fileEntry : input.entrySet()) {
            inputMap.put(new PathName(fileEntry.getKey().split("/"), null), fileEntry.getValue());
        }
        Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(outputMap.size());
        for (Map.Entry<PathName, Collection<T>> pathEntry : outputMap.entrySet()) {
            output.put(StringUtil.join("/", pathEntry.getKey().getPathComponents()), pathEntry.getValue());
        }
        return output;
    }
    
    public boolean pathNameMatches(String matcher, String matchee) {
        return pathNameMatches(new PathName(matcher.split("/"), null), new PathName(matchee.split("/"), null));
    }
}
