package com.coverity.security.pie.policy.securitymanager.fact;

import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;
import com.coverity.security.pie.util.collapser.PropertyCollapser;

public class PropertyNameFactMetaData implements FactMetaData {
    
    private static final PropertyNameFactMetaData instance = new PropertyNameFactMetaData();
    
    private PropertyNameFactMetaData() {
    }
    
    public static PropertyNameFactMetaData getInstance() {
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
        return CsvActionFactMetaData.getInstance();
    }

}
