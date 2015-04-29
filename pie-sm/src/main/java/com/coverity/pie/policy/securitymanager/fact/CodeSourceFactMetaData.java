package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.NullStringCollapser;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.policy.securitymanager.CodeSourceCollapser;

public class CodeSourceFactMetaData implements FactMetaData {

    private static final CodeSourceFactMetaData instance = new CodeSourceFactMetaData();
    
    private CodeSourceFactMetaData() {
    }
    
    public static CodeSourceFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return policyConfig.getBoolean("collapseLibDir", true) ? CodeSourceCollapser.getInstance() : NullStringCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return CodeSourceCollapser.pathMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return PermissionClassFactMetaData.getInstance();
    }

}
