package com.coverity.security.pie.policy.securitymanager.fact;

import com.coverity.security.pie.core.EqualityStringMatcher;
import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.NullStringCollapser;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;
import com.coverity.security.pie.core.UnsupportedFactMetaData;

public class SocketNameFactMetaData implements FactMetaData {
    
    private static final SocketNameFactMetaData instance = new SocketNameFactMetaData();
    
    private SocketNameFactMetaData() {
    }
    
    public static SocketNameFactMetaData getInstance() {
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
