package com.coverity.pie.core;

public interface FactMetaData {
    public StringCollapser getCollapser();
    public boolean matches(String matcher, String matchee);
    public FactMetaData getChildFactMetaData(String fact);
}
