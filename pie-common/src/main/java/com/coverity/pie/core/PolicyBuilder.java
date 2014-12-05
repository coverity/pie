package com.coverity.pie.core;

/**
 * This interface represents a policy builder which update and build a policy based on observed policy violations.
 * Implementations should generally expose additional methods which a policy enforcement engine can use to read and
 * enforce the effective policy (and subsequently report violations back to the builder).
 * 
 * Implementations should extract their implementation-specific configurations from the PieConfig passed into init().
 * 
 */
public interface PolicyBuilder {
    
    /**
     * Get the name of this policy builder.
     * 
     * @return The name of this policy builder.
     */
    public String getName();
    
    /**
     * Initialize this policy using the global PIE configuration. This method will be called
     * before any others.
     * 
     * @param pieConfig The global PIE Configuration.
     */
    public void init(PieConfig pieConfig);
    
    /**
     * Is this policy enabled?
     * 
     * @return True iff the policy is enabled.
     */
    public boolean isEnabled();
    
    /**
     * The builder should save its policy, updating the old policy to accommodate any violations
     * it has observed.
     */
    public void savePolicy();
    
    /**
     * Serialize any policy violations this builder has recorded. The exact value can be
     * implementation-specific, but should be understood by the registerPolicyViolations() method
     * of this class.
     * 
     * @return A serialized String representing observed policy violations.
     */
    public String getPolicyViolations();
    
    /**
     * Registers the serialized policy violations with this builder. These violations should
     * be reflected in the saved policy upon a subsequent call to savePolicy().
     * 
     * @param policyViolations A serialized String representing policy violations, as originally
     * returned from getPolicyViolations().
     */
    public void registerPolicyViolations(String policyViolations);
}
