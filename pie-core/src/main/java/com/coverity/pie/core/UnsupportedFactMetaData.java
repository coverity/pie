package com.coverity.pie.core;

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
