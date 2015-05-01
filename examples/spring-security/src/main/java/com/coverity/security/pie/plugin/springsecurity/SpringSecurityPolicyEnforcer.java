package com.coverity.security.pie.plugin.springsecurity;

import javax.servlet.ServletContext;

import com.coverity.security.pie.core.PieConfig;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.PolicyEnforcer;

public class SpringSecurityPolicyEnforcer implements PolicyEnforcer {

    public static final String SPRING_SECURITY_POLICY_ATTRIBUTE = "com.coverity.pie.plugin.springsecurity.CONTEXT";
    
    private SpringSecurityPolicy policy;
    private PolicyConfig policyConfig;
    
    @Override
    public SpringSecurityPolicy getPolicy() {
        return policy;
    }

    @Override
    public PolicyConfig getPolicyConfig() {
        return policyConfig;
    }

    @Override
    public void init(PieConfig pieConfig) {
        policy = new SpringSecurityPolicy();
        policyConfig = new PolicyConfig(policy.getName(), pieConfig);
        policy.setPolicyConfig(policyConfig);
    }

    @Override
    public void applyPolicy(ServletContext cx) {
        cx.setAttribute(SPRING_SECURITY_POLICY_ATTRIBUTE, this);
    }

    @Override
    public void shutdown() {
    }

}
