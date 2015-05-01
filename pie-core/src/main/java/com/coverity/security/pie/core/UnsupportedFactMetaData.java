package com.coverity.security.pie.core;

/**
 * An implementation of FactMetaData which can be used by security policy implementations when for fact instances they
 * do not expect or do not support.
 */
public class UnsupportedFactMetaData implements FactMetaData {

    private static final UnsupportedFactMetaData instance = new UnsupportedFactMetaData();
    
    private UnsupportedFactMetaData() {
    }
    
    public static UnsupportedFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        throw new UnsupportedOperationException();
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        throw new UnsupportedOperationException();
    }

}
