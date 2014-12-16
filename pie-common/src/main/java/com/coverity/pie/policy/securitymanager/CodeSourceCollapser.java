package com.coverity.pie.policy.securitymanager;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;

public class CodeSourceCollapser implements StringCollapser {
    
    private static final CodeSourceCollapser instance = new CodeSourceCollapser();
    
    private CodeSourceCollapser() {
    }
    
    public static CodeSourceCollapser getInstance() {
        return instance;
    }

    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        Map<String, Collection<T>> outputMap = new HashMap<>();
        
        for (Map.Entry<String, Collection<T>> inputEntry : input.entrySet()) {
            String key = inputEntry.getKey();
            int idx = key.indexOf("/WEB-INF/classes/");
            if (idx >= 0) {
                key = key.substring(0, idx) + "/WEB-INF/classes/-";
            }
            
            idx = key.indexOf("/WEB-INF/lib/");
            if (idx >= 0) {
                key = key.substring(0, idx) + "/WEB-INF/lib/-";
            }
            
            if (!outputMap.containsKey(key)) {
                List<T> list = new ArrayList<T>();
                list.addAll(inputEntry.getValue());
                outputMap.put(key, list);
            } else {
                outputMap.get(key).addAll(inputEntry.getValue());
            }
            
        }
        
        return outputMap;
    }
    
    public static boolean pathMatches(String matcher, String matchee) {
        char lastChar = matcher.charAt(matcher.length()-1);
        if (lastChar == '-') {
            return matchee.substring(0, matcher.length()-1).equals(matcher.substring(0,  matcher.length()-1));
        }
        if (lastChar == '*') {
            if (!matchee.substring(0, matcher.length()-1).equals(matcher.substring(0,  matcher.length()-1))) {
                return false;
            }
            return !matchee.substring(matcher.length()).contains("/");
        }
        return matcher.equals(matchee);
    }

}
