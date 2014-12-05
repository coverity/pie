package com.coverity.pie.policy.csp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.util.AntPathMatcher;

public class CspPolicy {
    private final List<CspPolicyEntry> cspPolicyEntries = new ArrayList<CspPolicyEntry>();
    
    public List<CspPolicyEntry> getPolicyEntries() {
        return cspPolicyEntries;
    }
    
    public String getPolicyForUri(String uri) {
        final AntPathMatcher pathMatcher = new AntPathMatcher();
        
        Map<String, Set<String>> directives = new HashMap<String, Set<String>>();        
        for (CspPolicyEntry cspPolicyEntry : cspPolicyEntries) {
            if (pathMatcher.match(cspPolicyEntry.getUri(), uri)) {
                for (Map.Entry<String, List<String>> directive : cspPolicyEntry.getDirectives().entrySet()) {
                    String directiveName = directive.getKey();
                    String[] directiveNames;
                    if (directiveName.equals("default-src")) {
                        directiveNames = getDirectiveNames();
                    } else {
                        directiveNames = new String[] { directiveName };
                    }
                    
                    for (String name : directiveNames) {
                        Set<String> values = directives.get(name);
                        if (values == null) {
                            values = new HashSet<String>();
                            directives.put(name, values);
                        }
                        for (String value : directive.getValue()) {
                            values.add(value);
                        }
                    }
                    
                }
            }
        }
        
        StringBuilder sb = new StringBuilder();
        for (String directiveName : getDirectiveNames()) {
            Set<String> directiveValues = directives.get(directiveName);
            if (directiveValues == null || directiveValues.size() == 0) {
                sb.append(directiveName).append(' ').append("'none'");
            } else {
                sb.append(directiveName);
                for (String value : directiveValues) {
                    sb.append(' ').append(value);
                }
            }
            sb.append(';');
        }
        sb.setLength(sb.length()-1);
        return sb.toString();
    }
    
    private static String[] getDirectiveNames() {
        return new String[] {"script-src", "object-src", "style-src", "img-src", "media-src", "frame-src", "font-src", "connect-src"};
    }
}
