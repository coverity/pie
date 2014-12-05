package com.coverity.pie.policy.csp;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import com.coverity.pie.core.AbstractPolicyEnforcer;
import com.coverity.pie.core.PolicyBuilder;

public class CspPolicyEnforcer extends AbstractPolicyEnforcer {

    private final CspPolicyBuilder policyBuilder = new CspPolicyBuilder();
    private CspEnforcementFilter cspEnforcementFilter;
    
    @Override
    protected PolicyBuilder getPolicyBuilder() {
        return policyBuilder;
    }
    
    @Override
    public void applyPolicy(ServletContext cx) {
        cspEnforcementFilter = new CspEnforcementFilter(policyBuilder);
        cspEnforcementFilter.refreshPolicy();
        FilterRegistration.Dynamic filterRegistration = cx.addFilter("cspEnforcementFilter", cspEnforcementFilter);
        filterRegistration.addMappingForUrlPatterns(null, false, "/*");
    }

    @Override
    public void shutdown() {
    }

    @Override
    public void refreshPolicy() {
        cspEnforcementFilter.refreshPolicy();
    }

}
