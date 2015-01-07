package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.EqualityStringMatcher;
import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.NullStringCollapser;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;

public class PermissionNameFactMetaData implements FactMetaData {

    private static final PermissionNameFactMetaData instance = new PermissionNameFactMetaData();
    
    private PermissionNameFactMetaData() {
    }
    
    public static PermissionNameFactMetaData getInstance() {
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
        return PermissionActionFactMetaData.getInstance();
    }

}
