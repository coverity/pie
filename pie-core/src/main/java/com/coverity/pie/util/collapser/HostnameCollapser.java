package com.coverity.pie.util.collapser;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.StringUtil;

public class HostnameCollapser extends AbstractPathCollapser implements StringCollapser {

    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("(([^:]*)://)?([a-zA-Z0-9\\-\\*\\.]*)(:([0-9]*))?");
    
    public HostnameCollapser(int collapseThreshold) {
        super("*", "*", collapseThreshold, 0);
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
    public boolean pathNameMatches(PathName matcher, PathName matchee) {
        // Never collapse quoted hostnames
        if (matchee.getPathComponents().length == 1 && matchee.getPathComponents()[0].charAt(0) == '\'') {
            return false;
        }
        return super.pathNameMatches(matcher, matchee);
    }

    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        
        Map<PathName, Collection<T>> inputMap = new HashMap<PathName, Collection<T>>(input.size());
        for (Map.Entry<String, Collection<T>> hostname : input.entrySet()) {
            if (hostname.getKey().charAt(0) == '\'') {
                // Discard 'none' entirely if other key exists
                if (hostname.getKey().equals("'none'") && input.size() > 1) {
                    continue;
                }
                
                inputMap.put(new PathName(new String[] { hostname.getKey() }, null), null);
            } else {
                
                final Matcher m = HOSTNAME_PATTERN.matcher(hostname.getKey());
                if (!m.matches()) {
                    throw new IllegalArgumentException("Unable to parse hostname: " + hostname.getKey());
                }
                
                String scheme = m.group(2);
                String[] host = m.group(3).split("\\.");
                String port = m.group(5);
                
                inputMap.put(new PathName(reverse(host), new String[] { scheme, port }), hostname.getValue());
            }
        }
        
        Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
        Map<String, Collection<T>> output = new HashMap<String, Collection<T>>(outputMap.size());
        for (Map.Entry<PathName, Collection<T>> pathName : outputMap.entrySet()) {
            if (pathName.getKey().getPathComponents().length == 1 && pathName.getKey().getPathComponents()[0].charAt(0) == '\'') {
                output.put(pathName.getKey().getPathComponents()[0], pathName.getValue());
            } else {
                String[] schemeAndPort = pathName.getKey().getNonPathComponents();
                StringBuilder hostname = new StringBuilder();
                if (schemeAndPort != null && schemeAndPort[0] != null) {
                    hostname.append(schemeAndPort[0]).append("://");
                }
                hostname.append(StringUtil.join(".", reverse(pathName.getKey().getPathComponents())));
                if (schemeAndPort != null && schemeAndPort[1] != null) {
                    hostname.append(":").append(schemeAndPort[1]);
                }
                output.put(hostname.toString(), pathName.getValue());
            }
        }
        return output;
    }
    
    private static PathName toPathName(String s) {
        if (s.charAt(0) == '\'') {
            return new PathName(new String[] { s }, null);
        } else {
            
            final Matcher m = HOSTNAME_PATTERN.matcher(s);
            if (!m.matches()) {
                throw new IllegalArgumentException("Unable to parse hostname: " + s);
            }
            
            String scheme = m.group(2);
            String[] host = m.group(3).split("\\.");
            String port = m.group(5);
            
            return new PathName(reverse(host), new String[] { scheme, port });
        }
    }
    
    public boolean pathNameMatches(String matcher, String matchee) {
        return pathNameMatches(toPathName(matcher), toPathName(matchee));
    }
}
