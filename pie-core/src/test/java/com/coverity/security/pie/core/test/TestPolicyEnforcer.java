package com.coverity.security.pie.core.test;

import com.coverity.security.pie.core.*;

import javax.servlet.ServletContext;

public class TestPolicyEnforcer implements PolicyEnforcer {

    private static TestPolicyEnforcer instance = null;

    public static TestPolicyEnforcer getInstance() {
        return instance;
    }

    private SimplePolicy policy;
    private PolicyConfig policyConfig;
    private boolean isApplied = false;

    public TestPolicyEnforcer() {
        if (instance != null) {
            throw new IllegalStateException("Cannot instantiate more than one TestPolicyEnforcer at a time.");
        }
        instance = this;
    }

    @Override
    public void init(PieConfig pieConfig) {
        this.policy = new SimplePolicy();
        this.policyConfig = new PolicyConfig(policy.getName(), pieConfig);
    }

    @Override
    public SimplePolicy getPolicy() {
        return policy;
    }

    @Override
    public PolicyConfig getPolicyConfig() {
        return policyConfig;
    }

    @Override
    public void applyPolicy(ServletContext cx) {
        isApplied = true;
    }

    @Override
    public void shutdown() {
        instance = null;
    }

    public boolean isApplied() {
        return isApplied;
    }
}
