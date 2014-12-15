package com.coverity.pie.policy.csp;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.Policy;
import com.coverity.pie.policy.csp.fact.UriFactMetaData;

public class CspRealPolicy extends Policy {

    private static final String[] DIRECTIVE_NAMES = new String[] {"script-src", "object-src", "style-src", "img-src", "media-src", "frame-src", "font-src", "connect-src"};
    
    @Override
    public String getName() {
        return "csp";
    }
    
    @Override
    public FactMetaData getRootFactMetaData() {
        return UriFactMetaData.getInstance();
    }
    
    public String getPolicyForUri(String uri) {
        Collection<String[]> grants = super.getGrants(uri, null, null);
        Map<String, Set<String>> directives = new HashMap<>();
        for (String[] grant : grants) {
            String directiveName = grant[1];
            String[] directiveNames;
            if (directiveName.equals("default-src")) {
                directiveNames = DIRECTIVE_NAMES;
            } else {
                directiveNames = new String[] { directiveName };
            }
            for (String name : directiveNames) {
                Set<String> values = directives.get(name);
                if (values == null) {
                    values = new HashSet<String>();
                    directives.put(name, values);
                }
                values.add(grant[2]);
            }
        }
        
        StringBuilder sb = new StringBuilder();
        for (String directiveName : DIRECTIVE_NAMES) {
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
    
    public void logViolation(URI documentUri, String directive, String blockedHost) {
        super.logViolation(documentUri.getPath(), directive, blockedHost);
    }
}
