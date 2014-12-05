package com.coverity.pie.policy.securitymanager;

import java.net.URL;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class RequestDatastore {
    
    private final Map<PermissionRequest, Long> requestCounts = new HashMap<>();
    
    public void logPermissionRequest(StackTraceElement[] stackTrace, URL codeSource, Permission permission) {
        for (StackTraceElement stackRow : stackTrace) {
            if (stackRow.getClassName().startsWith("java.")
                    || stackRow.getClassName().startsWith("sun.")) {
                continue;
            }
            
            if (permission.getActions() == null || permission.getActions().length() == 0) {
                logPermissionRequest(new PermissionRequest(System.currentTimeMillis(), codeSource.toString(), stackRow.getClassName(), permission.getClass().getName(), permission.getName(), null));
            } else {
                String[] actions = permission.getActions().split(",");
                for (String action : actions) {
                    logPermissionRequest(new PermissionRequest(System.currentTimeMillis(), codeSource.toString(), stackRow.getClassName(), permission.getClass().getName(), permission.getName(), action));
                }
            }
        }
    }
    
    public void logPermissionRequest(PermissionRequest permissionRequest) {
        synchronized (requestCounts) {
            if (!requestCounts.containsKey(permissionRequest)) {
                requestCounts.put(permissionRequest, 1L);
            } else {
                requestCounts.put(permissionRequest, requestCounts.get(permissionRequest)+1L);
            }
        }
    }
    
    public Collection<PermissionRequest> getPermissionRequests() {
        Collection<PermissionRequest> permissionRequests = new ArrayList<PermissionRequest>();
        synchronized (requestCounts) {
            permissionRequests.addAll(requestCounts.keySet());
        }
        return permissionRequests;
    }
}
