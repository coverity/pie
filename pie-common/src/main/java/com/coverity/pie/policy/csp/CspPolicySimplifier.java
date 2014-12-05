package com.coverity.pie.policy.csp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.coverity.pie.util.collapser.HostnameCollapser;
import com.coverity.pie.util.collapser.UriCspDirectiveCollapser;

public class CspPolicySimplifier {
    public static CspPolicy simplifyPolicy(CspPolicy policy) {
        
        final HostnameCollapser hostnameCollapser = new HostnameCollapser(2);
        final UriCspDirectiveCollapser uriCspDirectiveCollapser = new UriCspDirectiveCollapser(2);
        
        boolean anyCollapsed = true;
        List<CspPolicyEntry> entries = new ArrayList<CspPolicyEntry>(policy.getPolicyEntries());
        
        while (anyCollapsed) {
            anyCollapsed = false;
            for (CspPolicyEntry entry : entries) {
                for (Map.Entry<String, List<String>> directive : entry.getDirectives().entrySet()) {
                    List<String> original = directive.getValue();
                    List<String> collapsed = new ArrayList<String>(hostnameCollapser.collapse(original));
                    if (original.size() != collapsed.size()) {
                        entry.getDirectives().put(directive.getKey(), collapsed);
                        anyCollapsed = true;
                    }
                }
            }
            
            List<CspPolicyEntry> newEntries = new ArrayList<CspPolicyEntry>(uriCspDirectiveCollapser.collapse(entries));
            if (newEntries.size() != entries.size()) {
                entries = newEntries;
                anyCollapsed = true;
            }
        }
        
        CspPolicy newPolicy = new CspPolicy();
        newPolicy.getPolicyEntries().addAll(entries);
        return newPolicy;
    }
}
