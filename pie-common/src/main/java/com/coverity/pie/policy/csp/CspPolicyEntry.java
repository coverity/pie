package com.coverity.pie.policy.csp;

import java.util.List;
import java.util.Map;

public class CspPolicyEntry {
    private final String uri;
    private final Map<String, List<String>> directives;
    
    public CspPolicyEntry(String uri, Map<String, List<String>> directives) {
        this.uri = uri;
        this.directives = directives;
    }
    public String getUri() {
        return uri;
    }
    public Map<String, List<String>> getDirectives() {
        return directives;
    }
}