package com.coverity.pie.policy.securitymanager.collapse;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import com.coverity.pie.util.collapser.FilePathCollapser;

public class FilePermissionCollapser implements Collapser {

    private static final Collection<String> SUPPORTED_PERMISSIONS = Collections.unmodifiableList(Arrays.asList("java.io.FilePermission"));
    
    private final FilePathCollapser filePathCollapser = new FilePathCollapser(2);
    
    @Override
    public Collection<String> supportedPermissions() {
        return SUPPORTED_PERMISSIONS; 
    }

    @Override
    public Collection<String> collapse(Collection<String> input) {
        return filePathCollapser.collapse(input);
    }

}
