package com.coverity.pie.core;

public interface FactMetaData {
    public StringCollapser getCollapser(PolicyConfig policyConfig);
    public boolean matches(String matcher, String matchee);
    public FactMetaData getChildFactMetaData(String fact);
}
