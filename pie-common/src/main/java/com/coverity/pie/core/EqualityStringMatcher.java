package com.coverity.pie.core;


public class EqualityStringMatcher implements StringMatcher {
    
    private static final EqualityStringMatcher instance = new EqualityStringMatcher();
    
    private EqualityStringMatcher() {
    }
    
    public static EqualityStringMatcher getInstance() {
        return instance;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return matcher.equals(matchee);
    }

}
