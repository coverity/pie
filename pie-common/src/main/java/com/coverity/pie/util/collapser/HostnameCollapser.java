package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.coverity.pie.util.StringUtil;

public class HostnameCollapser extends AbstractPathCollapser<Void> {

    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("(([^:]*)://)?([a-zA-Z0-9\\-\\*\\.]*)(:([0-9]*))?");
    
    public HostnameCollapser(int collapseThreshold) {
        super("*", "*", collapseThreshold);
    }

    public Collection<String> collapse(Collection<String> input) {
        
        // Remove duplicates and 'none' if there's any other names
        input = new HashSet<String>(input);
        if (input.contains("'none'") && input.size() > 1) {
            input.remove("'none'");
        }
        
        Map<PathName, Collection<Void>> inputMap = new HashMap<PathName, Collection<Void>>(input.size());
        for (String hostname : input) {
            if (hostname.charAt(0) == '\'') {
                inputMap.put(new PathName(new String[] { hostname }, null), null);
            } else {
                
                final Matcher m = HOSTNAME_PATTERN.matcher(hostname);
                if (!m.matches()) {
                    throw new IllegalArgumentException("Unable to parse hostname: " + hostname);
                }
                
                String scheme = m.group(2);
                String[] host = m.group(3).split("\\.");
                String port = m.group(5);
                
                inputMap.put(new PathName(reverse(host), new String[] { scheme, port }), null);
            }
        }
        Map<PathName, Collection<Void>> outputMap = collapsePaths(inputMap);
        Collection<String> output = new ArrayList<String>(outputMap.size());
        for (PathName pathName : outputMap.keySet()) {
            if (pathName.getPathComponents().length == 1 && pathName.getPathComponents()[0].charAt(0) == '\'') {
                output.add(pathName.getPathComponents()[0]);
            } else {
                String[] schemeAndPort = pathName.getNonPathComponents();
                StringBuilder hostname = new StringBuilder();
                if (schemeAndPort != null && schemeAndPort[0] != null) {
                    hostname.append(schemeAndPort[0]).append("://");
                }
                hostname.append(StringUtil.join(".", reverse(pathName.getPathComponents())));
                if (schemeAndPort != null && schemeAndPort[1] != null) {
                    hostname.append(":").append(schemeAndPort[1]);
                }
                output.add(hostname.toString());
            }
        }
        return output;
    }
    
    private static String[] reverse(String[] input) {
        for (int i = 0; i < input.length/2; i++) {
            String a = input[i];
            input[i] = input[input.length-1-i];
            input[input.length-1-i] = a;
        }
        return input;
    }
    
    @Override
    protected boolean arePathsMatch(String[] a, String[] b) {
        if (a.length == 1 && a[0].charAt(0) == '\'') {
            return false;
        }
        if (b.length == 1 && b[0].charAt(0) == '\'') {
            return false;
        }
        return super.arePathsMatch(a, b);
    }
    
    @Override
    protected boolean pathNameMatches(PathName matcher, PathName matchee) {
        // Never collapse quoted hostnames
        if (matchee.getPathComponents().length == 1 && matchee.getPathComponents()[0].charAt(0) == '\'') {
            return false;
        }
        return super.pathNameMatches(matcher, matchee);
    }
}
