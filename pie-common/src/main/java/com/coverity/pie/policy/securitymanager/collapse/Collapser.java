package com.coverity.pie.policy.securitymanager.collapse;

import java.util.Collection;

public interface Collapser {
    public Collection<String> supportedPermissions();
    public Collection<String> collapse(Collection<String> input);
}
