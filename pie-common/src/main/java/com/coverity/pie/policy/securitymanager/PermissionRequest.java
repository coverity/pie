package com.coverity.pie.policy.securitymanager;

public class PermissionRequest {
    private final long requestTime;
    private final String codeSource;
    private final String className;
    private final String permissionClassName;
    private final String permissionName;
    private final String permissionAction;
    
    public PermissionRequest(long requestTime, String codeSource, String className, String permissionClassName, String permissionName, String permissionAction) {
        this.requestTime = requestTime;
        this.codeSource = codeSource;
        this.className = className;
        this.permissionClassName = permissionClassName;
        this.permissionName = permissionName;
        this.permissionAction = permissionAction;
    }
    
    public long getRequestTime() {
        return requestTime;
    }

    public String getCodeSource() {
        return codeSource;
    }

    public String getClassName() {
        return className;
    }

    public String getPermissionClassName() {
        return permissionClassName;
    }

    public String getPermissionName() {
        return permissionName;
    }

    public String getPermissionAction() {
        return permissionAction;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((className == null) ? 0 : className.hashCode());
        result = prime * result
                + ((codeSource == null) ? 0 : codeSource.hashCode());
        result = prime
                * result
                + ((permissionAction == null) ? 0 : permissionAction.hashCode());
        result = prime
                * result
                + ((permissionClassName == null) ? 0 : permissionClassName
                        .hashCode());
        result = prime * result
                + ((permissionName == null) ? 0 : permissionName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PermissionRequest other = (PermissionRequest) obj;
        if (className == null) {
            if (other.className != null)
                return false;
        } else if (!className.equals(other.className))
            return false;
        if (codeSource == null) {
            if (other.codeSource != null)
                return false;
        } else if (!codeSource.equals(other.codeSource))
            return false;
        if (permissionAction == null) {
            if (other.permissionAction != null)
                return false;
        } else if (!permissionAction.equals(other.permissionAction))
            return false;
        if (permissionClassName == null) {
            if (other.permissionClassName != null)
                return false;
        } else if (!permissionClassName.equals(other.permissionClassName))
            return false;
        if (permissionName == null) {
            if (other.permissionName != null)
                return false;
        } else if (!permissionName.equals(other.permissionName))
            return false;
        return true;
    }
    
}
