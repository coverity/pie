package com.coverity.pie.policy.securitymanager.collapse;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import com.coverity.pie.util.collapser.PropertyCollapser;

public class PropertyPermissionCollapser implements Collapser {

    private static final Collection<String> SUPPORTED_PERMISSIONS = Collections.unmodifiableList(Arrays.asList("java.util.PropertyPermission"));
    
    private final PropertyCollapser propertyCollapser = new PropertyCollapser(2);
    
    @Override
    public Collection<String> supportedPermissions() {
        return SUPPORTED_PERMISSIONS; 
    }

    @Override
    public Collection<String> collapse(Collection<String> input) {
        return propertyCollapser.collapse(input);
    }

}
