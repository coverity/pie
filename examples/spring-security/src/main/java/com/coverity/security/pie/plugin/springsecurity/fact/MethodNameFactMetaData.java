package com.coverity.security.pie.plugin.springsecurity.fact;

import com.coverity.security.pie.core.EqualityStringMatcher;
import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.NullStringCollapser;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;
import com.coverity.security.pie.core.UnsupportedFactMetaData;

public class MethodNameFactMetaData implements FactMetaData {

    private static final MethodNameFactMetaData instance = new MethodNameFactMetaData();
    
    private MethodNameFactMetaData() {
    }
    
    public static MethodNameFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return NullStringCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return EqualityStringMatcher.getInstance().matches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return UnsupportedFactMetaData.getInstance();
    }

}
