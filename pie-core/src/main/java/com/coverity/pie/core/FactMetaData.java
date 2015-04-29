package com.coverity.pie.core;

/**
 * Represents the semantics of a fact within a security policy.
 */
public interface FactMetaData {
    /**
     * Returns a StringCollapser appropriate for this fact's semantics. The behavior of the StringCollapser may behave
     * according to particulars of the policyConfig argument.
     *
     * @param policyConfig The policy's configuration, which may have directives relevant to this type of fact.
     * @return The StringCollapser instance appropriate for this fact.
     */
    public StringCollapser getCollapser(PolicyConfig policyConfig);

    /**
     * This decides if a concrete instance of a fact matches a fact definition from the security policy.
     * @param matcher The security policy's fact.
     * @param matchee The concrete instance of a fact.
     * @return Whether or not the security policy's fact applies to the instance of a fact.
     */
    public boolean matches(String matcher, String matchee);

    /**
     * Gets the metadata object associated with the child fact. The particular semantics of the child may depend on the
     * concrete instance of the fact being handled. For instance, with the Java SecurityManager, the semantics of child
     * facts of a java.io.FilePermission (which represent file paths) are distinct from the child facts of a
     * java.net.SocketPermission (which represent hosts).
     * @param fact The concrete value of the fact for which child metadata is desired.
     * @return The child metadata.
     */
    public FactMetaData getChildFactMetaData(String fact);
}
