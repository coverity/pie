package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.collapser.PropertyCollapser;

public class JmxMBeanClassNameFactMetaData implements FactMetaData {

    private static final JmxMBeanClassNameFactMetaData instance = new JmxMBeanClassNameFactMetaData();
    
    private JmxMBeanClassNameFactMetaData() {
    }
    
    public static JmxMBeanClassNameFactMetaData getInstance() {
        return instance;
    }
    
    private final PropertyCollapser propertyCollapser = new PropertyCollapser(2);
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return propertyCollapser;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return propertyCollapser.pathNameMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return JmxMBeanMemberFactMetaData.getInstance();
    }

}
