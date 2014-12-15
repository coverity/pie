package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.EqualityStringMatcher;
import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.NullStringCollapser;
import com.coverity.pie.core.StringCollapser;

public class PermissionClassFactMetaData implements FactMetaData {

    private static final PermissionClassFactMetaData instance = new PermissionClassFactMetaData();
    
    private PermissionClassFactMetaData() {
    }
    
    public static PermissionClassFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser() {
        return NullStringCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return EqualityStringMatcher.getInstance().matches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        switch (fact) {
        case "java.io.FilePermission":
            return FileNameFactMetaData.getInstance();
        case "java.util.PropertyPermission":
            return PropertyNameFactMetaData.getInstance();
        default:
            return PermissionNameFactMetaData.getInstance();
        }
    }

}
