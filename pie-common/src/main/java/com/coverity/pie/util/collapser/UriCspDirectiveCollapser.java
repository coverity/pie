package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.coverity.pie.policy.csp.CspPolicyEntry;
import com.coverity.pie.util.StringUtil;

public class UriCspDirectiveCollapser extends AbstractPathCollapser<Map<String, List<String>>> {

    public UriCspDirectiveCollapser(int collapseThreshold) {
        super("*", "**", collapseThreshold);
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
}
