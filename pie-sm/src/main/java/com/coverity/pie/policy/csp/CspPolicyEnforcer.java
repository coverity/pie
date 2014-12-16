package com.coverity.pie.policy.csp;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.Policy;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.PolicyEnforcer;

public class CspPolicyEnforcer implements PolicyEnforcer {

    private CspPolicy policy;
    private PolicyConfig policyConfig;
    private CspEnforcementFilter cspEnforcementFilter;
    
    @Override
    public void init(PieConfig pieConfig) {
        policy = new CspPolicy();
        policyConfig = new PolicyConfig(policy.getName(), pieConfig);
    }
    
    @Override
    public Policy getPolicy() {
        return policy;
    }
    
    @Override
    public PolicyConfig getPolicyConfig() {
        return policyConfig;
    }
    
    @Override
    public void applyPolicy(ServletContext cx) {
        cspEnforcementFilter = new CspEnforcementFilter(policy, policyConfig);
        FilterRegistration.Dynamic filterRegistration = cx.addFilter("cspEnforcementFilter", cspEnforcementFilter);
        filterRegistration.addMappingForUrlPatterns(null, false, "/*");
    }

    @Override
    public void shutdown() {
    }

}
