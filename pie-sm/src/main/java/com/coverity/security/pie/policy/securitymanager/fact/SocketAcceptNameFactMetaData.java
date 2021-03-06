package com.coverity.security.pie.policy.securitymanager.fact;

import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;
import com.coverity.security.pie.core.UnsupportedFactMetaData;
import com.coverity.security.pie.core.WildcardStringCollapser;

public class SocketAcceptNameFactMetaData implements FactMetaData {
    
    private static final SocketAcceptNameFactMetaData instance = new SocketAcceptNameFactMetaData();
    
    private SocketAcceptNameFactMetaData() {
    }
    
    public static SocketAcceptNameFactMetaData getInstance() {
        return instance;
    }
    
    private final WildcardStringCollapser wildcardStringCollapser = new WildcardStringCollapser("*:0");
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return wildcardStringCollapser;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return wildcardStringCollapser.matches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return UnsupportedFactMetaData.getInstance();
    }

}
