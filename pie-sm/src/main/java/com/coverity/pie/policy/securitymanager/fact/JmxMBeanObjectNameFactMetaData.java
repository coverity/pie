package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.EqualityStringMatcher;
import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.NullStringCollapser;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;

public class JmxMBeanObjectNameFactMetaData implements FactMetaData {

    private static final JmxMBeanObjectNameFactMetaData instance = new JmxMBeanObjectNameFactMetaData();
    
    private JmxMBeanObjectNameFactMetaData() {
    }
    
    public static JmxMBeanObjectNameFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        // FIXME: Object name matching and collapsing is non-trivial
        // https://docs.oracle.com/javase/7/docs/api/javax/management/ObjectName.html
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
