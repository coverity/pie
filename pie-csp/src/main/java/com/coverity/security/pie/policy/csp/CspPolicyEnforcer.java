package com.coverity.security.pie.policy.csp;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.Policy;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.PolicyEnforcer;

/**
 * CSP implementation of a PIE policy enforcer.
 */
public class CspPolicyEnforcer implements PolicyEnforcer {

    private CspPolicy policy;
    private PolicyConfig policyConfig;
    private CspEnforcementFilter cspEnforcementFilter;
    
    @Override
    public void init(PieConfig pieConfig) {
        policy = new CspPolicy();
        policyConfig = new PolicyConfig(policy.getName(), pieConfig);
        policy.setPolicyConfig(policyConfig);
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
