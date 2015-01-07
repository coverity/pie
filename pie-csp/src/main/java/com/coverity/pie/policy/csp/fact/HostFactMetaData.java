package com.coverity.pie.policy.csp.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.core.UnsupportedFactMetaData;
import com.coverity.pie.util.collapser.HostnameCollapser;

public class HostFactMetaData implements FactMetaData {

    private static final HostFactMetaData instance = new HostFactMetaData();
    
    private HostFactMetaData() {
    }
    
    public static HostFactMetaData getInstance() {
        return instance;
    }
    
    private final HostnameCollapser hostnameCollapser = new HostnameCollapser(2);
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return hostnameCollapser;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return hostnameCollapser.pathNameMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return UnsupportedFactMetaData.getInstance();
    }

}
