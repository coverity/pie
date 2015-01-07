package com.coverity.pie.util.collapser;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.StringUtil;


public class UriCspDirectiveCollapser extends AbstractPathCollapser implements StringCollapser {
    public UriCspDirectiveCollapser(int collapseThreshold) {
        super("*", "**", collapseThreshold, 2);
    }
    
    @Override
    protected boolean pathNameMatches(PathName matcher, PathName matchee) {
        // Do not collapse URI paths down to the root.
        if (matcher.getPathComponents().length == 1
                && (matcher.getPathComponents()[0].equals("*") || matcher.getPathComponents()[0].equals("**"))) {
            return false;
        }
        if (matcher.getPathComponents().length == 2 && matcher.getPathComponents()[0].equals("")
                && (matcher.getPathComponents()[1].equals("*") || matcher.getPathComponents()[1].equals("**"))) {
            return false;
        }
        return super.pathNameMatches(matcher, matchee);
    }

    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        Map<PathName, Collection<T>> inputMap = new HashMap<PathName, Collection<T>>(input.size());
        for (Map.Entry<String, Collection<T>> entry : input.entrySet()) {
            inputMap.put(new PathName(entry.getKey().split("/", -1), null), entry.getValue());
        }
        Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(outputMap.size());
        for (Map.Entry<PathName, Collection<T>> pathNameEntry : outputMap.entrySet()) {
            output.put(StringUtil.join("/", pathNameEntry.getKey().getPathComponents()), pathNameEntry.getValue());
        }
        return output;
    }
    
    public boolean pathNameMatches(String matcher, String matchee) {
        // Use the super path name matcher so that we can match against root URI
        return super.pathNameMatches(new PathName(matcher.split("/", -1), null), new PathName(matchee.split("/", -1), null));
    }
}
