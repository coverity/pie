package com.coverity.pie.core;

/**
 * A base class for PolicyEnforcers which utilize a PolicyBuilder to build and update their policy.
 */
public abstract class AbstractPolicyEnforcer implements PolicyEnforcer {

    protected abstract PolicyBuilder getPolicyBuilder();
    
    @Override
    public String getName() {
        return getPolicyBuilder().getName();
    }
    
    @Override
    public void init(PieConfig pieConfig) {
        getPolicyBuilder().init(pieConfig);
    }

    @Override
    public boolean isEnabled() {
        return getPolicyBuilder().isEnabled();
    }

    @Override
    public void savePolicy() {
        getPolicyBuilder().savePolicy();
    }

    @Override
    public String getPolicyViolations() {
        return getPolicyBuilder().getPolicyViolations();
    }

    @Override
    public void registerPolicyViolations(String policyViolations) {
        getPolicyBuilder().registerPolicyViolations(policyViolations);        
    }

}
