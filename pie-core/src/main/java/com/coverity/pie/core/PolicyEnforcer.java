package com.coverity.pie.core;

import javax.servlet.ServletContext;

/**
 * 
 * Represents classes which enforce a policy in a servlet context and which update their policy
 * based on recorded policy violations. Most implementations should be backed by a PolicyBuilder
 * implementation and delegate requests to save, update, and record violations to that builder.
 * An abstract class which provides that delegation is available as AbstractPolicyEnforcer.
 *  
 * @seealso AbstractPolicyEnforcer
 * 
 */
public interface PolicyEnforcer {
    
    public Policy getPolicy();
    public PolicyConfig getPolicyConfig();
    
    public void init(PieConfig pieConfig);
    
    /**
     * Apply the policy to the servlet context being initialized. This enforcer should configure
     * itself to both apply its policy to permission requests and keep an internal record of any
     * policy violations. 
     * 
     * @param cx The servlet context currently being initialized.
     */
    public void applyPolicy(ServletContext cx);
    
    /**
     * The ServletContext to which this policy is applied is shutting down. The enforcer
     * should do any cleanup it needs.
     */
    public void shutdown();
    
}
