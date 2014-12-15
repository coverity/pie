package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.policy.csp.CspPolicyEntry;
import com.coverity.pie.util.StringUtil;


public class UriCspDirectiveCollapser extends AbstractPathCollapser implements StringCollapser {
    public UriCspDirectiveCollapser(int collapseThreshold) {
        super("*", "**", collapseThreshold, 0);
    }

    public Collection<CspPolicyEntry> collapse(Collection<CspPolicyEntry> input) {
        Map<PathName, Collection<Map<String, List<String>>>> inputMap = new HashMap<PathName, Collection<Map<String, List<String>>>>(input.size());
        for (CspPolicyEntry policyEntry : input) {
            inputMap.put(new PathName(policyEntry.getUri().split("/"), null), Collections.singleton(policyEntry.getDirectives()));
        }
        Map<PathName, Collection<Map<String, List<String>>>> outputMap = collapsePaths(inputMap);
        Collection<CspPolicyEntry> output = new ArrayList<CspPolicyEntry>(outputMap.size());
        for (Map.Entry<PathName, Collection<Map<String, List<String>>>> pathNameEntry : outputMap.entrySet()) {
            final String uri = StringUtil.join("/", pathNameEntry.getKey().getPathComponents());
            final Map<String, List<String>> directives = new HashMap<String, List<String>>();
            
            for (Map<String, List<String>> outputDirectives : pathNameEntry.getValue()) {
                for (Map.Entry<String, List<String>> directive : outputDirectives.entrySet()) {
                    if (!directives.containsKey(directive.getKey())) {
                        directives.put(directive.getKey(), new ArrayList<String>(directive.getValue()));
                    } else {
                        directives.get(directive.getKey()).addAll(directive.getValue());
                    }
                }
            }
            
            output.add(new CspPolicyEntry(uri, directives));
        }
        return output;
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
            inputMap.put(new PathName(entry.getKey().split("/"), null), entry.getValue());
        }
        Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(outputMap.size());
        for (Map.Entry<PathName, Collection<T>> pathNameEntry : outputMap.entrySet()) {
            output.put(StringUtil.join("/", pathNameEntry.getKey().getPathComponents()), pathNameEntry.getValue());
        }
        return output;
    }
    
    public boolean pathNameMatches(String matcher, String matchee) {
        return pathNameMatches(new PathName(matcher.split("/"), null), new PathName(matchee.split("/"), null));
    }
}
