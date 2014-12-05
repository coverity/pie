package com.coverity.pie.policy.securitymanager;

import java.net.URL;
import java.security.Permission;
import java.util.Arrays;
import java.util.Collection;

import com.coverity.pie.core.PieConfig;
import com.coverity.pie.core.PolicyBuilder;
import com.coverity.pie.policy.securitymanager.collapse.Collapser;
import com.coverity.pie.policy.securitymanager.collapse.FilePermissionCollapser;
import com.coverity.pie.policy.securitymanager.collapse.PropertyPermissionCollapser;

public class SecurityManagerPolicyBuilder implements PolicyBuilder {
    
    private SecurityManagerConfig securityManagerConfig;
    private RequestDatastore requestDatastore = new RequestDatastore();
    
    private final Collection<Collapser> collapsers = Arrays.asList(
            new FilePermissionCollapser(),
            new PropertyPermissionCollapser()
            );

    @Override
    public String getName() {
        return "SecurityManager";
    }
    
    @Override
    public void init(PieConfig pieConfig) {
        securityManagerConfig = new SecurityManagerConfig(pieConfig);
    }
    
    @Override
    public boolean isEnabled() {
        return securityManagerConfig.isEnabled();
    }
    
    @Override
    public void savePolicy() {
        PolicyFileUtil.buildPolicyFile(securityManagerConfig.getPolicyPath(),
                securityManagerConfig.isSimplePolicy(),
                requestDatastore.getPermissionRequests(),
                collapsers);
    }

    @Override
    public String getPolicyViolations() {
        StringBuilder sb = new StringBuilder();
        for (PermissionRequest permissionRequest : requestDatastore.getPermissionRequests()) {
            sb.append(permissionRequest.getCodeSource()).append("\t")
                .append(permissionRequest.getClassName()).append("\t")
                .append(permissionRequest.getPermissionClassName()).append("\t")
                .append(permissionRequest.getPermissionName()).append("\t")
                .append(permissionRequest.getPermissionAction()).append("\n");
        }
        return sb.toString();
    }

    @Override
    public void registerPolicyViolations(String policyViolations) {
        String[] lines = policyViolations.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.equals("")) {
                continue;
            }
            
            try {
                String[] fields = line.split("\t");
                PermissionRequest permissionRequest = new PermissionRequest(
                        Long.parseLong(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5]);
                requestDatastore.logPermissionRequest(permissionRequest);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid line: " + line);
            }
        }
        
    }
    
    public SecurityManagerConfig getConfig() {
        return securityManagerConfig;
    }
    public void registerPolicyViolation(StackTraceElement[] stackTrace, URL codeSource, Permission permission) {
        requestDatastore.logPermissionRequest(stackTrace, codeSource, permission);
    }


}
